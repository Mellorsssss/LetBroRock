#include "utils.h"
#include "dr_api.h"
#include "dr_ir_decode.h"
#include "dr_ir_instr.h"
#include "dr_tools.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <ctype.h>
#include <dirent.h>
#include <libunwind-ptrace.h>
#include <libunwind-x86_64.h>
#include <libunwind.h>
#include <linux/hw_breakpoint.h>
#include <string>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unordered_set>

#define X86

long perf_event_open(struct perf_event_attr *event_attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, event_attr, pid, cpu, group_fd, flags);
}

uint64_t get_pc(ucontext_t *ucontext)
{
#if defined(__x86_64__)
  return (uint64_t)(ucontext->uc_mcontext.gregs[REG_RIP]);
#elif defined(__aarch64__)
  return (uint64_t)(ucontext->uc_mcontext.pc);
#endif
}

bool find_next_branch(ThreadContext &tcontext, uint64_t pc,int length)
{
  amed_context context;
#if defined(__x86_64__)
  context.architecture = AMED_ARCHITECTURE_X86;
  context.machine_mode = AMED_MACHINE_MODE_64;
#elif defined(__aarch64__)
  context.architecture = AMED_ARCHITECTURE_AARCH64;
  context.machine_mode = AMED_MACHINE_MODE_64;
#endif

  context.length = length;
  context.address = (uint8_t *)pc;

  amed_context *pcontext = &context;

  amed_insn insn;

  // TODO: partial decoding instructions non-branch instructions
  while (amed_decode_insn(pcontext, &insn))
  {
    uint64_t temp_pc = (uint64_t)(pcontext->address);
    DEBUG("current pc: %lx", temp_pc);

    pcontext->address += insn.length;
    pcontext->length -= insn.length;

    // amed_print_insn(buffer, &context, &insn, &formatter);
    // DEBUG("%s(len: %d, %d args)", buffer, insn.length, insn.argument_count);

    if (!is_control_flow_transfer(insn))
    {
      continue;
    }

    // find a branch and fill in its from address
    tcontext.set_from_addr(temp_pc);
    return true;
  }

  return false;
}

void enable_perf_sampling(pid_t tid, int perf_fd)
{
  DEBUG("enable perf sampling for %d", tid);
  if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) == -1)
  {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    exit(EXIT_FAILURE);
  }
}

std::pair<uint64_t, bool> check_branch_if_taken(ThreadContext &tcontext, ucontext_t &context, bool static_eval)
{
  amed_context acontext;

  uint64_t from_addr = tcontext.get_branch().from_addr;
#if defined(__x86_64__)
  acontext.architecture = AMED_ARCHITECTURE_X86;
  acontext.machine_mode = AMED_MACHINE_MODE_64;
#elif defined(__aarch64__)
  acontext.architecture = AMED_ARCHITECTURE_AARCH64;
  acontext.machine_mode = AMED_MACHINE_MODE_64;
#endif
  acontext.length = INT32_MAX;
  acontext.address = (uint8_t *)from_addr;

  DEBUG("check_branch_if_taken: decode the instruction at %lx", from_addr);
  amed_insn insn;
  if (amed_decode_insn(&acontext, &insn))
  {
    assert(is_control_flow_transfer(insn) && "should be a control-flow transfer instruction");
    // if (!is_control_flow_transfer(insn))
    // return std::make_pair(UNKNOWN_ADDR, false);
    auto [target, taken] = static_eval ? static_evaluate(tcontext, from_addr, acontext, insn) : evaluate(tcontext.get_dr_context(), *tcontext.get_instr(), acontext, insn, &context);
    if (taken)
    {
      if (static_eval)
      {
        tcontext.add_static_branch();
      }
      else
      {
        tcontext.add_dynamic_branch();
      }
    }

    return std::make_pair(target, taken);
  }
  else
  {
    ERROR("check_branch_if_taken: fail to decode the cti");
  }

  return std::make_pair(0, false);
}

std::vector<pid_t> get_tids(pid_t target_pid, const std::vector<pid_t>& exclue_targets, int max_size)
{
  std::vector<pid_t> tids;
  std::unordered_set<pid_t> tids_set;
  while (true)
  {
    std::string path_cpp = "/proc/" + std::to_string(target_pid) + "/task";
    char *path = new char[path_cpp.length() + 1];
    strcpy(path, path_cpp.c_str());

    struct dirent *entry;
    DIR *dir = opendir(path);
    if (dir == NULL)
    {
      exit(-1);
    }

    bool has_new_tid = false;
    while ((entry = readdir(dir)) != NULL && tids.size() < max_size)
    {
      std::string tid(entry->d_name);
      if (std::all_of(tid.begin(), tid.end(), isdigit))
      {
        pid_t tid_number = std::atol(tid.c_str());

        if (std::any_of(exclue_targets.begin(), exclue_targets.end(), [&](pid_t id) {
          return id == tid_number;
        }))
          continue;

        if (tids_set.find(tid_number) == tids_set.end())
        {
          tids.push_back((pid_t)tid_number);
          tids_set.insert(tid_number);
          has_new_tid = true;
        }
      }
    }
    closedir(dir);
    if (!has_new_tid && tids.size() > 0)
      break;
    delete []path;
  }

  std::string log_str = "get_tids: Find tids:";
  for (auto &tid : tids)
  {
    log_str += std::to_string(tid) + " ";
  }

  INFO("%s", log_str.c_str());
  return tids;
}

bool is_control_flow_transfer(amed_insn &insn)
{
  switch (insn.categories[1])
  {
  case AMED_CATEGORY_BRANCH:
  case AMED_CATEGORY_CALL:
  case AMED_CATEGORY_RET:
    return true;
  default:
    return false;
  }
}

void init_dr_mcontext(dr_mcontext_t *mcontext, ucontext_t *ucontext)
{
  mcontext->size = sizeof(dr_mcontext_t);
  mcontext->flags = DR_MC_ALL;

#if defined(__x86_64__)
  mcontext->xdi = ucontext->uc_mcontext.gregs[REG_RDI];
  mcontext->xsi = ucontext->uc_mcontext.gregs[REG_RSI];
  mcontext->xbp = ucontext->uc_mcontext.gregs[REG_RBP];
  mcontext->xsp = ucontext->uc_mcontext.gregs[REG_RSP];
  mcontext->xax = ucontext->uc_mcontext.gregs[REG_RAX];
  mcontext->xbx = ucontext->uc_mcontext.gregs[REG_RBX];
  mcontext->xcx = ucontext->uc_mcontext.gregs[REG_RCX];
  mcontext->xdx = ucontext->uc_mcontext.gregs[REG_RDX];
  mcontext->xip = (byte *)ucontext->uc_mcontext.gregs[REG_RIP];
  mcontext->xflags = ucontext->uc_mcontext.gregs[REG_EFL];
#elif defined(__aarch64__)
  mcontext->r0 = ucontext->uc_mcontext.regs[0];
  mcontext->r1 = ucontext->uc_mcontext.regs[1];
  mcontext->r2 = ucontext->uc_mcontext.regs[2];
  mcontext->r3 = ucontext->uc_mcontext.regs[3];
  mcontext->r4 = ucontext->uc_mcontext.regs[4];
  mcontext->r5 = ucontext->uc_mcontext.regs[5];
  mcontext->r6 = ucontext->uc_mcontext.regs[6];
  mcontext->r7 = ucontext->uc_mcontext.regs[7];
  mcontext->r8 = ucontext->uc_mcontext.regs[8];
  mcontext->r9 = ucontext->uc_mcontext.regs[9];
  mcontext->r10 = ucontext->uc_mcontext.regs[10];
  mcontext->r11 = ucontext->uc_mcontext.regs[11];
  mcontext->r12 = ucontext->uc_mcontext.regs[12];
  mcontext->r13 = ucontext->uc_mcontext.regs[13];
  mcontext->r14 = ucontext->uc_mcontext.regs[14];
  mcontext->r15 = ucontext->uc_mcontext.regs[15];
  mcontext->r16 = ucontext->uc_mcontext.regs[16];
  mcontext->r17 = ucontext->uc_mcontext.regs[17];
  mcontext->r18 = ucontext->uc_mcontext.regs[18];
  mcontext->r19 = ucontext->uc_mcontext.regs[19];
  mcontext->r20 = ucontext->uc_mcontext.regs[20];
  mcontext->r21 = ucontext->uc_mcontext.regs[21];
  mcontext->r22 = ucontext->uc_mcontext.regs[22];
  mcontext->r23 = ucontext->uc_mcontext.regs[23];
  mcontext->r24 = ucontext->uc_mcontext.regs[24];
  mcontext->r25 = ucontext->uc_mcontext.regs[25];
  mcontext->r26 = ucontext->uc_mcontext.regs[26];
  mcontext->r27 = ucontext->uc_mcontext.regs[27];
  mcontext->r28 = ucontext->uc_mcontext.regs[28];
  mcontext->r29 = ucontext->uc_mcontext.regs[29];
  mcontext->r30 = ucontext->uc_mcontext.regs[30];
  mcontext->r31 = ucontext->uc_mcontext.regs[31];
  mcontext->pc = (byte *)ucontext->uc_mcontext.pc;
  mcontext->xflags = ucontext->uc_mcontext.pstate;
#endif
}

std::pair<uint64_t, bool> static_evaluate(ThreadContext &tcontext, uint64_t pc, amed_context &context, amed_insn &insn)
{
  return std::make_pair(UNKNOWN_ADDR, true);
#ifdef NO_STATIC
  return std::make_pair(UNKNOWN_ADDR, true);
#endif
  assert(is_control_flow_transfer(insn) && "instruction should be a control-flow transfer instruction.");
  if ((AMED_CATEGORY_BRANCH == insn.categories[1] && AMED_CATEGORY_UNCONDITIONALLY == insn.categories[2]) || AMED_CATEGORY_CALL == insn.categories[1])
  {
    instr_t d_insn;
    instr_init(tcontext.get_dr_context(), &d_insn);

    DEBUG("static_evaluate: try to decode the instruction");
    if (decode(tcontext.get_dr_context(), (byte *)pc, &d_insn) == nullptr)
    {
      ERROR("fail to decode the instruction using dynamorio");
    }
    else
    {
      DEBUG("static_evaluate: succeed to decode the instruction using dynamorio");
    }

    opnd_t target_op = instr_get_target(&d_insn);
    uint64_t target_addr = UNKNOWN_ADDR;
    if (opnd_is_immed(target_op))
    {
      if (opnd_is_immed_int(target_op))
      {
        target_addr = opnd_get_immed_int(target_op);
      }
      else if (opnd_is_immed_int64(target_op))
      {
        target_addr = opnd_get_immed_int64(target_op);
      }
      else
      {
        assert(0 && "direct control flow trasfer should only go to int address!");
      }
      WARNING("statically evaluated address from immed: %#lx", target_addr);
    }
    else if (opnd_is_abs_addr(target_op))
    {
      target_addr = (uint64_t)opnd_compute_address(target_op, nullptr);
      if (target_addr == 0)
      {
        ERROR("fail to comput the addr");
      }
      WARNING("statically evaluated address from abs_addr: %#lx", target_addr);
    }
    else if (opnd_is_pc(target_op))
    {
      target_addr = (uint64_t)opnd_get_pc(target_op);
      if (target_addr == 0)
      {
        ERROR("fail to comput the addr");
      }
      // WARNING("statically evaluated address from pc: %#lx", target_addr);
    }
    else
    {
      DEBUG("static_evaluate: the target is not imm");
    }

    instr_free(tcontext.get_dr_context(), &d_insn);
    WARNING("taken branch: %#lx -> %#lx", pc, target_addr);
    return std::make_pair(target_addr, target_addr == UNKNOWN_ADDR ? false : true);
  }
  else
  {
    return std::make_pair(UNKNOWN_ADDR, false);
  }
}

std::pair<uint64_t, bool> evaluate(void *dr_context, instr_t& d_insn, amed_context &context, amed_insn &insn, ucontext_t *ucontext)
{
#if defined(__x86_64__)
  return evaluate_x86(dr_context, d_insn, context, insn, ucontext);
#elif define(aarch64)
  return evaluate_arm(dr_context, d_insn, context, insn, ucontext);
#endif
}

std::pair<uint64_t, bool> evaluate_x86(void *dr_context, instr_t& d_insn, amed_context &context, amed_insn &insn, ucontext_t *ucontext)
{
  assert(is_control_flow_transfer(insn) && "instruction should be a control-flow transfer instruction.");

  dr_mcontext_t mcontext;
  init_dr_mcontext(&mcontext, ucontext);
  byte *addr = (byte *)(get_pc(ucontext));

  if (decode(dr_context, addr, &d_insn) == nullptr)
  {
    ERROR("fail to decode the instruction using dynamorio");
  }
  else
  {
    // instr_disassemble(dr_context, &d_insn, STDOUT);
    DEBUG("\nsucceed to decode the instruction using dynamorio");
  }

  // judge what kind of the instruction is
  if (AMED_CATEGORY_BRANCH == insn.categories[1])
  {
    assert(instr_is_cbr(&d_insn) || instr_is_ubr(&d_insn) || instr_is_mbr(&d_insn));
  }
  else if (AMED_CATEGORY_CALL == insn.categories[1])
  {
    assert(instr_is_call(&d_insn));
  }
  else if (AMED_CATEGORY_RET == insn.categories[1])
  {
    assert(instr_is_return(&d_insn));
  }
  else
  {
    puts("interworking branch.");
  }

  opnd_t target_op = instr_get_target(&d_insn);
  app_pc target_address = nullptr;
  uint64_t target_addr = UNKNOWN_ADDR;
  if (opnd_is_memory_reference(target_op))
  {
    DEBUG("evaluate_x86: is memory ref");
  }
  else if (opnd_is_pc(target_op))
  {
    DEBUG("evaluate_x86: is pc");
  }
  else if (opnd_is_reg(target_op))
  {
    DEBUG("evaluate_x86: is reg");
  }

  // dr_print_opnd(dr_context, STDOUT, target_op, "the opnd is :");

  if (opnd_is_immed(target_op))
  {
    if (opnd_is_immed_int(target_op))
    {
      target_addr = opnd_get_immed_int(target_op);
    }
    else
    {
      assert(0 && "direct control flow trasfer should only go to int address!");
    }
  }
  else if (opnd_is_pc(target_op))
  {
    target_address = opnd_get_pc(target_op); // TODO: is this always offset?
    if (target_address == nullptr)
    {
      ERROR("fail to compute the address of operand");
    }
    target_addr = (uint64_t)(target_address);
  }
  else if (opnd_is_reg(target_op))
  {
    target_addr = reg_get_value(opnd_get_reg(target_op), &mcontext); // TODO: is this always offset?
    // if the instruction is ret, then just jump to the exact address
    if (!instr_is_return(&d_insn)) {
      target_addr += insn.length;
    } else {
      target_addr = *((uint64_t*)target_addr);
    }
  }
  else
  {
    target_address = opnd_compute_address(target_op, &mcontext);
    if (target_address == nullptr)
    {
      ERROR("fail to compute the address of operand");
    }
    target_addr = (uint64_t)(target_address);
  }

  if (target_addr == UNKNOWN_ADDR)
  {
    puts("fail to get the target address of the operand");
    exit(EXIT_FAILURE);
  }
  else
  {
    DEBUG("the target address of the current instruction is %#lx", target_addr);
  }

  bool taken = true;
  if (instr_is_cbr(&d_insn))
  {
    DEBUG("begin to eval cbr");
    uint32_t eflags = mcontext.xflags;

    switch (instr_get_opcode(&d_insn))
    {
    case OP_jb:
    case OP_jb_short:
      taken = mcontext.xflags & EFLAGS_CF; // CF=1
      break;
    case OP_jbe:
    case OP_jbe_short:
      taken = (mcontext.xflags & EFLAGS_CF) || (mcontext.xflags & EFLAGS_ZF); // CF=1 or ZF=1
      break;
    case OP_jecxz:
      taken = mcontext.xcx & 0xFFFFFFFF;
      break;
    case OP_jl:
    case OP_jl_short:
      taken = (mcontext.xflags & EFLAGS_SF) != (mcontext.xflags & EFLAGS_OF); // SF!=OF
      break;
    case OP_jle:
    case OP_jle_short:
      taken = (mcontext.xflags & EFLAGS_ZF) || ((mcontext.xflags & EFLAGS_SF) != (mcontext.xflags & EFLAGS_OF)); // ZF=1 | SF!=OF
      break;
    case OP_jnb:
    case OP_jnb_short:
      taken = !(mcontext.xflags & EFLAGS_CF); // CF=0
      break;
    case OP_jnbe:
    case OP_jnbe_short:
      taken = !(mcontext.xflags & EFLAGS_CF) && !(mcontext.xflags & EFLAGS_ZF); // CF=0 and ZF=0
      break;
    case OP_jnl:
    case OP_jnl_short:
      taken = (mcontext.xflags & EFLAGS_SF) == (mcontext.xflags & EFLAGS_OF); // SF=OF
      break;
    case OP_jnle:
    case OP_jnle_short:
      taken = (mcontext.xflags & EFLAGS_ZF) && ((mcontext.xflags & EFLAGS_SF) == (mcontext.xflags & EFLAGS_OF)); // ZF=1 and SF=OF
      break;
    case OP_jno:
    case OP_jno_short:
      taken = !(mcontext.xflags & EFLAGS_OF); // OF=0
      break;
    case OP_jnp:
    case OP_jnp_short:
      taken = !(mcontext.xflags & EFLAGS_PF); // PF=0
      break;
    case OP_jns:
    case OP_jns_short:
      taken = !(mcontext.xflags & EFLAGS_SF); // SF=0
      break;
    case OP_jnz:
    case OP_jnz_short:
      taken = !(mcontext.xflags & EFLAGS_ZF); // ZF=0
      break;
    case OP_jo:
    case OP_jo_short:
      taken = mcontext.xflags & EFLAGS_OF; // OF=1
      break;
    case OP_jp:
    case OP_jp_short:
      taken = mcontext.xflags & EFLAGS_PF; // PF=1
      break;
    case OP_js:
    case OP_js_short:
      taken = mcontext.xflags & EFLAGS_SF; // SF=1
      break;
    case OP_jz:
    case OP_jz_short:
      taken = mcontext.xflags & EFLAGS_ZF; // ZF=1
      break;
    default:
      // Handle other conditional branches as needed
      assert(0 && "unhandled jump instrcution.");
      break;
    }

    if (taken)
    {
      DEBUG("the conditional branch is taken");
    }
    else
    {
      DEBUG("the conditional branch is not taken");
    }
  }
  else
  {
    DEBUG("the unconditional branch is taken");
  }

  // handle the cbr

  // WARNING("dynamically evaluated address %#lx", target_addr);
  if (taken)
  {
    WARNING("taken branch: %#lx -> %#lx", get_pc(ucontext), target_addr);
  }
  else
  {
    // since not taken, target addr will be the next instruction
    target_addr = get_pc(ucontext) + insn.length;
    INFO("continue from %#lx", target_addr);
  }
  return std::make_pair(target_addr, taken);
}

std::pair<uint64_t, bool> evaluate_arm(void *dr_context, amed_context &context, amed_insn &insn, ucontext_t *ucontext)
{
// TODO(guichuan): determin if an cti instruction is taken
#if defined(aarch64)
  assert(is_control_flow_transfer(insn) && "instruction should be a control-flow transfer instruction.");

  dr_mcontext_t mcontext;
  init_dr_mcontext(&mcontext, ucontext);
  instr_t d_insn;
  instr_init(dr_context, &d_insn);
  byte *addr = (byte *)(get_pc(ucontext));

  if (decode(dr_context, addr, &d_insn) == nullptr)
  {
    ERROR("fail to decode the instruction using dynamorio");
  }
  else
  {
    // instr_disassemble(dr_context, &d_insn, STDOUT);
    DEBUG("\nsucceed to decode the instruction using dynamorio");
  }

  // judge what kind of the instruction is
  if (AMED_CATEGORY_BRANCH == insn.categories[1])
  {
    assert(instr_is_cbr(&d_insn) || instr_is_ubr(&d_insn) || instr_is_mbr(&d_insn));
  }
  else if (AMED_CATEGORY_CALL == insn.categories[1])
  {
    assert(instr_is_call(&d_insn));
  }
  else if (AMED_CATEGORY_RET == insn.categories[1])
  {
    assert(instr_is_return(&d_insn));
  }
  else
  {
    puts("interworking branch.");
  }

  opnd_t target_op = instr_get_target(&d_insn);
  app_pc target_address = nullptr;
  uint64_t target_addr = UNKNOWN_ADDR;
  if (opnd_is_memory_reference(target_op))
  {
    DEBUG("evaluate_arm: is memory ref");
  }
  else if (opnd_is_pc(target_op))
  {
    DEBUG("evaluate_arm: is pc");
  }
  else if (opnd_is_reg(target_op))
  {
    DEBUG("evaluate_arm: is reg");
  }

  // dr_print_opnd(dr_context, STDOUT, target_op, "the opnd is :");

  if (opnd_is_immed(target_op))
  {
    if (opnd_is_immed_int(target_op))
    {
      target_addr = opnd_get_immed_int(target_op);
    }
    else
    {
      assert(0 && "direct control flow trasfer should only go to int address!");
    }
  }
  else if (opnd_is_pc(target_op))
  {
    target_address = opnd_get_pc(target_op); // TODO: is this always offset?
    if (target_address == nullptr)
    {
      ERROR("fail to compute the address of operand");
    }
    target_addr = (uint64_t)(target_address);
  }
  else if (opnd_is_reg(target_op))
  {
    target_addr = reg_get_value(opnd_get_reg(target_op), &mcontext) + insn.length; // TODO: is this always offset?
  }
  else
  {
    target_address = opnd_compute_address(target_op, &mcontext);
    if (target_address == nullptr)
    {
      ERROR("fail to compute the address of operand");
    }
    target_addr = (uint64_t)(target_address);
  }

  if (target_addr == UNKNOWN_ADDR)
  {
    puts("fail to get the target address of the operand");
    exit(EXIT_FAILURE);
  }
  else
  {
    DEBUG("the target address of the current instruction is %#lx", target_addr);
  }

  bool taken = true;
  if (instr_is_cbr(&d_insn))
  {
    uint32_t eflags = mcontext.xflags;

    switch (instr_get_opcode(&d_insn))
    {
    // TODO:
    case OP_b:
    case OP_bl:
    case OP_blr:
    case OP_br:
    case OP_blrab:
    case OP_blrabz:
    case OP_braaz:
    case OP_brab:
    case OP_brabz:
      taken = true;
      break;

    // TODO: following OP code should be handled seperately
    case OP_bcond:
    case OP_cbnz:
    case OP_cbz:
    case OP_tbnz:
    case OP_tbz:
      // TODO: handle the conditonal jump
      taken = true;
      break;
    default:
      // Handle other conditional branches as needed
      assert(0 && "unhandled jump instruction.");
      break;
    }

    std::string log_str = "the conditional branch is ";
    if (!taken)
      log_str += "not ";
    log_str += "taken";
    DEBUG("%s", log_str.c_str());
  }
  else
  {
    DEBUG("the unconditional branch is taken");
  }

  // handle the cbr
  instr_free(dr_context, &d_insn);

  // WARNING("dynamically evaluated address %#lx", target_addr);
  if (taken)
  {
    WARNING("taken branch: %#lx -> %#lx", get_pc(ucontext), target_addr);
  }
  else
  {
    // since not taken, target addr will be the next instruction
    target_addr = get_pc(ucontext) + insn.length;
    INFO("continue from %#lx", target_addr);
  }
  return std::make_pair(target_addr, taken);
#else
  return std::make_pair(UNKNOWN_ADDR, false);
#endif
}

void print_backtrace()
{
  return;
  unw_cursor_t cursor;
  unw_context_t context;

  unw_getcontext(&context);
  unw_init_local(&cursor, &context);

  while (unw_step(&cursor) > 0)
  {
    unw_word_t offset, pc;
    char symbol[512];

    unw_get_reg(&cursor, UNW_REG_IP, &pc);

    if (unw_get_proc_name(&cursor, symbol, sizeof(symbol), &offset) == 0)
    {
      WARNING("[%lx] %s + 0x%lx\n", (unsigned long)pc, symbol, (unsigned long)offset);
    }
    else
    {
      WARNING("[%lx] <unknown>\n", (unsigned long)pc);
    }
  }
}

int tgkill(pid_t group_id, pid_t tid, int signo)
{
  return syscall(SYS_tgkill, group_id, tid, signo);
}