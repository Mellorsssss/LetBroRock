#include "utils.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <ctype.h>
#include <dirent.h>
#include <linux/hw_breakpoint.h>
#include <string>
#include <sys/syscall.h>
#include <unordered_set>

long perf_event_open(struct perf_event_attr *event_attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, event_attr, pid, cpu, group_fd, flags);
}

std::pair<branch, bool> find_next_unresolved_branch(uint64_t pc, const thread_context &tcontext, const user_context &ucontext)
{
  printf("Branch pc: %llx\n", pc);
  while (true)
  {
    auto res = find_next_branch(pc);
    if (!res.second)
    {
      printf("Fail to find a branch until the end of the code.\n");
      return res;
    }
    else
    {
      printf("from addr: %llx\n", res.first.from_addr);
      branch br = res.first;
      // handle the breakpoint
      if (br.to_addr == UNKNOWN_ADDR)
      {
        printf("Should handle the breakpoint\n");
        return res;
      }
    }
  }

  return std::make_pair(branch{}, false);
}

std::pair<branch, bool> find_next_branch(uint64_t pc)
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

  /* allocate buffer for formatter */
  // TODO: remove the internal malloc with memory pool
  char *buffer = (char *)malloc(256);
  uint64_t cur_pc = pc;
  // TODO: partial decoding instructions non-branch instructions
  while (amed_decode_insn(pcontext, &insn))
  {
    uint64_t temp_pc = cur_pc;
    printf("current pc: %llx\n", temp_pc);
    cur_pc += insn.length;
    pcontext->address += insn.length;
    pcontext->length -= insn.length;

    amed_print_insn(buffer, &context, &insn, &formatter);
    printf("%s(len: %d)\n", buffer, insn.length);

    if (!insn.may_branch)
    {
      continue;
    }
    if (AMED_CATEGORY_BRANCH == insn.categories[1])
    {
      /* explicit branch:
         un|conditional branch */
      puts(AMED_CATEGORY_CONDITIONALLY == insn.categories[2] ? "instruction branch conditionally." : "instruction branch unconditionally.");

      return std::make_pair(branch{
                                .from_addr = temp_pc,
                                .to_addr = UNKNOWN_ADDR,
                            },
                            true);
    }
    else
    {
      puts("interworking branch.");
    }
  }
  free(buffer);
  return std::make_pair(branch{}, false);
}

void enable_perf_sampling(pid_t tid, int perf_fd)
{
  printf("enable perf sampling for %d\n", tid);
  if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) == -1)
  {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    exit(EXIT_FAILURE);
  }
}

void disable_perf_sampling(pid_t tid, int perf_fd)
{
  if (close(perf_fd) != 0) {
    perror("close");
    exit(EXIT_FAILURE);
  }
  return;
  // TODO: dead code here
  if (ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0) == -1)
  {
    perror("ioctl(PERF_EVENT_IOC_DISABLE)");
    exit(EXIT_FAILURE);
  }
}

std::pair<uint64_t, bool> record_branch_if_taken(branch &br, user_context &context)
{
  amed_formatter formatter = {0};
  formatter.lower_case = true;

  /* allocate buffer for formatter */
  // TODO: remove the internal malloc with memory pool
  char *buffer = (char *)malloc(256);
  // TODO: implement this function
  // For now, we just check if the code at br.from_addr is a branch instruction
  amed_context acontext;

  // TODO: support more arch
  acontext.architecture = AMED_ARCHITECTURE_X86;
  acontext.machine_mode = AMED_MACHINE_MODE_64;
  // TODO: set to precise length
  acontext.length = INT32_MAX;
  acontext.address = (uint8_t *)br.from_addr;

  printf("try to decode the instruction at %#x\n", br.from_addr);
  amed_insn insn;
  if (amed_decode_insn(&acontext, &insn))
  {
    amed_print_insn(buffer, &acontext, &insn, &formatter);
    printf("%s\n", buffer);
    if (insn.may_branch && AMED_CATEGORY_BRANCH == insn.categories[1])
    {
      printf("Pass! This is a branch instrucion!\n");
      return std::make_pair(0, true);
    }
    else
    {
      printf("Not a branch\n");
    }
  }
  else
  {
    printf("fail to decode the instruction\n");
    exit(EXIT_FAILURE);
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

  printf("Find tids:");
  for (auto &tid : tids)
  {
    printf("%ld ", tid);
  }
  printf("\n");
  return tids;
}

void set_breakpoint(pid_t tid, uint64_t addr)
{
  struct perf_event_attr pe;

  memset(&pe, 0, sizeof(struct perf_event_attr));
  pe.type = PERF_TYPE_BREAKPOINT;
  pe.size = sizeof(struct perf_event_attr);
  pe.config = 0;
  pe.bp_type = HW_BREAKPOINT_X;
  pe.bp_addr = (uintptr_t)(addr);
  pe.bp_len = 8;
  pe.sample_period = 1; // make sure every breakpoint will cause a overflow
  pe.disabled = 1;
  pe.exclude_kernel = 1;

  int perf_fd;
  printf("enter the set breakpoint, errno is %d\n", errno);
  while ((perf_fd = syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0)) == -1)
  {
    perror("perf_event_open");
    printf("breakpoint is in use");
    exit(EXIT_FAILURE);
    sched_yield();
  }

  // TODO: use a better way to handle the errors
  struct f_owner_ex owner;
  owner.type = F_OWNER_TID;
  owner.pid = tid;
  if (fcntl(perf_fd, F_SETOWN_EX, &owner) == -1)
  {
    perror("F_SETSIG");
    exit(EXIT_FAILURE);
  }

  if (fcntl(perf_fd, F_SETSIG, SIGIO) == -1)
  {
    perror("F_SETSIG");
    exit(EXIT_FAILURE);
  }

  int flags = fcntl(perf_fd, F_GETFL, 0);
  if (flags == -1)
  {
    perror("F_GETFL");
    exit(EXIT_FAILURE);
  }

  if (fcntl(perf_fd, F_SETFL, flags | O_ASYNC) == -1)
  {
    perror("F_SETFL");
    exit(EXIT_FAILURE);
  }

  // reset the signal handler
  struct sigaction sa;
  sa.sa_sigaction = breakpoint_handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGIO, &sa, NULL) == -1 || errno != 0)
  {
    perror("sigaction");
    return;
  }

  // open perf_event
  // ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
  printf("successfully set breakpoint at %#x\n", addr);
}

void remove_breakpoint(int perf_fd, uint64_t addr)
{
  if (close(perf_fd) != 0) {
    perror("close");
    exit(EXIT_FAILURE);
  }

  // reset the signal handler
  struct sigaction sa;
  sa.sa_sigaction = sampling_handler;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGIO, &sa, NULL) == -1)
  {
    perror("sigaction");
    return;
  }

  printf("successfully remove breakpoint at %#x of %d\n", addr, perf_fd);
}

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext)
{
  printf("si_code:%d\n", info->si_code);
  printf("Breakpoint handler: the fd is %d handled by %d\n", info->si_fd, syscall(SYS_gettid));

  ucontext_t *uc = (ucontext_t *)ucontext;

  uint64_t pc = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
  branch br = branch{.from_addr = pc};
  user_context u_context{};
  auto target_taken = record_branch_if_taken(br, u_context);
  if (target_taken.second)
  {
    remove_breakpoint(info->si_fd, pc);
    perf_events_enable(syscall(SYS_gettid));
  }
  else
  {
    printf("Continue to get breakpoint\n");
  }
  // enable_perf_sampling(syscall(SYS_gettid), info->si_fd);
  return;
}

void sampling_handler(int signum, siginfo_t *info, void *ucontext)
{
  // pid_t target_pid = perf_id_map.get(info->si_fd);
  pid_t target_pid = syscall(SYS_gettid);
  ucontext_t *uc = (ucontext_t *)ucontext;

  // TODO: it seems the info->si_code is always the POLL_IN
  printf("Sampling handler: the fd is %d, handled by %d\n", info->si_fd, syscall(SYS_gettid));

  disable_perf_sampling(target_pid, info->si_fd);

  // get PC
  uint64_t pc = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
  printf("ip: %#x\n", pc);

  thread_context tcontext{
      .tid = target_pid,
  };

  const user_context shit{};
  auto branch_ok = find_next_unresolved_branch(pc, tcontext, shit);
  if (branch_ok.second)
  {
    branch br = branch_ok.first;
    set_breakpoint(target_pid, br.from_addr);
  }

  // TODO: remove the sleep. Currently we use it to debug the output.
  sleep(1);
}

int perf_events_enable(pid_t tid, pid_t main_tid)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_INSTRUCTIONS;
    pe.sample_period = 100000000;
    pe.disabled = 1;
    // pe.inherit = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int perf_fd = syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0);
    if (perf_fd == -1)
    {
        perror("perf_event_open");
        return -1;
    }

    // TODO: use a better way to handle the errors
    struct f_owner_ex owner;
    if (main_tid != -1)
    {
        owner.type = F_OWNER_PID;
        owner.pid = main_tid;
    }
    else
    {
        owner.type = F_OWNER_TID;
        owner.pid = tid;
    }
    fcntl(perf_fd, F_SETOWN_EX, &owner);
    fcntl(perf_fd, F_SETSIG, SIGIO);
    fcntl(perf_fd, F_SETFL, O_NONBLOCK | O_ASYNC);

    // open perf_event
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

    printf("perf events enable for %d->%d(fd: %d)\n", owner.pid, syscall(SYS_gettid), perf_fd);
    return perf_fd;
}