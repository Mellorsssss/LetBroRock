#include "utils.h"
#include "Logger.h"
#include "dr_api.h"
#include "dr_ir_decode.h"
#include "dr_ir_instr.h"
#include "dr_tools.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <ctype.h>
#include <dirent.h>
#include <linux/hw_breakpoint.h>
#include <string>
#include <sys/syscall.h>
#include <unordered_set>

#define X86

long perf_event_open(struct perf_event_attr *event_attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, event_attr, pid, cpu, group_fd, flags);
}

uint64_t get_pc(ucontext_t *ucontext)
{
  // TODO: support more archs
  return (uint64_t)(ucontext->uc_mcontext.gregs[REG_RIP]);
}

std::pair<branch, bool> find_next_branch(thread_context &tcontext, uint64_t pc)
{
  amed_context context;
  // TODO: support more arch
  context.architecture = AMED_ARCHITECTURE_X86;
  context.machine_mode = AMED_MACHINE_MODE_64;

  // TODO: set to precise length. But actually there must exist a control-flow transfering instruciton
  context.length = INT32_MAX;
  context.address = (uint8_t *)pc;

  amed_context *pcontext = &context;

  amed_formatter formatter = {0};
  formatter.lower_case = true;

  amed_insn insn;

  // TODO: remove the internal malloc with memory pool
  char *buffer = (char *)malloc(256);

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

    // test if the branch could be statically evaluated
    auto static_res = static_evaluate(tcontext, temp_pc, *pcontext, insn);
    if (!static_res.second)
    {
      free(buffer);
      return std::make_pair(branch{
                                .from_addr = temp_pc,
                                .to_addr = static_res.first,
                            },
                            true);
    }

    free(buffer);
    // this branch needs to be evaluated dynamically
    return std::make_pair(branch{
                              .from_addr = temp_pc,
                              .to_addr = UNKNOWN_ADDR,
                          },
                          true);
  }

  free(buffer);
  return std::make_pair(branch{}, false);
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

void disable_perf_sampling(pid_t tid, int perf_fd)
{
  if (ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0) == -1)
  {
    perror("ioctl(PERF_EVENT_IOC_DISABLE)");
    exit(EXIT_FAILURE);
  }

  if (close(perf_fd) != 0)
  {
    perror("close");
    exit(EXIT_FAILURE);
  }
  return;
}

std::pair<uint64_t, bool> record_branch_if_taken(thread_context &tcontext, branch &br, ucontext_t &context)
{
  amed_formatter formatter = {0};
  formatter.lower_case = true;

  /* allocate buffer for formatter */
  // TODO: remove the internal malloc with memory pool
  char *buffer = (char *)malloc(256);
  amed_context acontext;

  // TODO: support more arch
  acontext.architecture = AMED_ARCHITECTURE_X86;
  acontext.machine_mode = AMED_MACHINE_MODE_64;
  acontext.length = INT32_MAX;
  acontext.address = (uint8_t *)br.from_addr;

  DEBUG("record_branch_if_taken: decode the instruction at %lx", br.from_addr);
  amed_insn insn;
  if (amed_decode_insn(&acontext, &insn))
  {
    // assert(is_control_flow_transfer(insn) && "should be a control-flow transfer instruction");
    if (!is_control_flow_transfer(insn))
      return std::make_pair(UNKNOWN_ADDR, false);
    return evaluate(tcontext.dr_context, acontext, insn, &context);
  }
  else
  {
    ERROR("record_branch_if_taken: fail to decode the instruction");
  }

  return std::make_pair(0, false);
}

std::vector<pid_t> get_tids(pid_t target_pid, bool exclue_target)
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
    while ((entry = readdir(dir)) != NULL)
    {
      std::string tid(entry->d_name);
      if (std::all_of(tid.begin(), tid.end(), isdigit))
      {
        pid_t tid_number = std::atol(tid.c_str());

        if (exclue_target && tid_number == target_pid)
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
  }

  std::string log_str = "get_tids: Find tids:";
  for (auto &tid : tids)
  {
    log_str += std::to_string(tid) + " ";
  }

  INFO("%s", log_str.c_str());
  return tids;
}

int perf_events_enable(pid_t tid)
{
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(struct perf_event_attr));
  pe.type = PERF_TYPE_HARDWARE;
  pe.size = sizeof(struct perf_event_attr);
  // pe.config = PERF_COUNT_HW_INSTRUCTIONS;
  pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
  pe.sample_period = 5000,000;
  pe.disabled = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;
  pe.wakeup_events = 1;

  int perf_fd = syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0);
  if (perf_fd == -1)
  {
    perror("perf_event_open");
    return -1;
  }

  struct f_owner_ex owner;
  owner.type = F_OWNER_TID;
  owner.pid = tid;

  if (fcntl(perf_fd, F_SETOWN_EX, &owner) != 0)
  {
    perror("F_SETOWN_EX");
    exit(EXIT_FAILURE);
  }
  if (fcntl(perf_fd, F_SETSIG, SIGIO) != 0)
  {
    perror("F_SETSIG");
    exit(EXIT_FAILURE);
  }
  if (fcntl(perf_fd, F_SETFL, (fcntl(perf_fd, F_GETFL, 0)) | O_NONBLOCK | O_ASYNC))
  {
    perror("F_SETFL");
    exit(EXIT_FAILURE);
  }

  // open perf_event
  if (ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0) != 0)
  {
    perror("PERF_EVENT_IOC_RESET");
    exit(EXIT_FAILURE);
  }

  DEBUG("perf_events_enable: for %d->%d(fd: %d)", owner.pid, syscall(SYS_gettid), perf_fd);
  if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) != 0)
  {
    perror("PERF_EVENT_IOC_ENABLE");
    exit(EXIT_FAILURE);
  }

  return perf_fd;
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
}

std::pair<uint64_t, bool> static_evaluate(thread_context &tcontext, uint64_t pc, amed_context &context, amed_insn &insn)
{
  assert(is_control_flow_transfer(insn) && "instruction should be a control-flow transfer instruction.");
  if ((AMED_CATEGORY_BRANCH == insn.categories[1] && AMED_CATEGORY_UNCONDITIONALLY == insn.categories[2]) || AMED_CATEGORY_CALL == insn.categories[1])
  {
    instr_t d_insn;
    instr_init(tcontext.dr_context, &d_insn);

    DEBUG("static_evaluate: try to decode the instruction");
    if (decode(tcontext.dr_context, (byte *)pc, &d_insn) == nullptr)
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
    }
    else
    {
      DEBUG("static_evaluate: the target is not imm");
    }

    instr_free(tcontext.dr_context, &d_insn);
    return std::make_pair(target_addr, target_addr == UNKNOWN_ADDR ? true : false);
  }
  else
  {
    return std::make_pair(UNKNOWN_ADDR, true);
  }
}

std::pair<uint64_t, bool> evaluate(void *dr_context, amed_context &context, amed_insn &insn, ucontext_t *ucontext)
{
  return evaluate_x86(dr_context, context, insn, ucontext);
}

std::pair<uint64_t, bool> evaluate_x86(void *dr_context, amed_context &context, amed_insn &insn, ucontext_t *ucontext)
{
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
    puts("call instruction");
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
    case OP_jb:
    case OP_jb_short:
      taken = mcontext.xflags & EFLAGS_CF; // CF=1
      break;
    case OP_jbe:
    case OP_jbe_short:
      taken = (mcontext.xflags & EFLAGS_CF) || (mcontext.xflags & EFLAGS_ZF); // CF=1 or ZF=1
      break;
    // TODO: it seems dynamorio doesn't support this
    // case OP_jc:
    //   taken = mcontext.xflags & EFLAGS_CF; // CF=1
    //   break;
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
    // TODO:
    // case OP_jnc:
    //   taken = !(mcontext.xflags & EFLAGS_CF); // CF=0
    //   break;
    // TODO:
    // case OP_jng:
    //   taken = (mcontext.xflags & EFLAGS_ZF) || ((mcontext.xflags & EFLAGS_SF) != (mcontext.xflags & EFLAGS_OF)); // ZF=1 or SF!=OF
    //   break;
    // case OP_jnge:
    //   taken = (mcontext.xflags & EFLAGS_SF) != (mcontext.xflags & EFLAGS_OF); // SF!=OF
    //   break;
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
      // TODO: it seems dynamorio doesn't support this case OP_jpe:
      // TODO: it seems dynamorio doesn't support this case OP_jpo:
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

  if (taken)
  {
    INFO("taken branch: %#lx -> %#lx", get_pc(ucontext), target_addr);
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
}

void logMessage(LogLevel level, const char *file, int line, const char *format, ...)
{
#ifdef LOG_LEVEL
  if (level < LOG_LEVEL)
  {
    return;
  }
#endif
  const char *levelStr[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
  const char *colorStr[] = {COLOR_DEBUG, COLOR_INFO, COLOR_WARNING, COLOR_ERROR};

  printf("%s[%s:%d] %s: %s", colorStr[level], file, line, levelStr[level], COLOR_RESET);

  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
  puts("");

  if (level == LOG_ERROR)
  {
    exit(EXIT_FAILURE);
  }
}