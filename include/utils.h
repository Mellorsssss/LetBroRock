#ifndef LBR_UTILS
#define LBR_UTILS
#include "amed.h"
#include "dbg.h"
#include "decoder.hpp"
#include <asm/unistd.h>
#include <fcntl.h>
#include <iostream>
#include <linux/perf_event.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/wait.h>
#include <vector>

typedef struct _branch
{
    uintptr_t from_addr;
    uintptr_t to_addr;
    uint8_t original_code; // the saved breakpoint-ed code
} branch;

typedef struct _thread_context {
    pid_t tid;
} thread_context;

typedef struct user_regs_struct user_context;
const uint64_t UNKNOWN_ADDR = 0;

long perf_event_open(struct perf_event_attr *event_attr, pid_t pid, int cpu,
                     int group_fd, unsigned long flags);


std::pair<branch, bool> find_next_unresolved_branch(uint64_t pc, const thread_context& tcontext, const user_context &ucontext);

std::pair<branch, bool> find_next_branch(uint64_t pc);

void disable_perf_sampling(pid_t tid, int perf_fd);

void enable_perf_sampling(pid_t tid, int perf_fd);

std::pair<uint64_t, bool> record_branch_if_taken(branch& br, user_context& context);

std::vector<pid_t> get_tids(pid_t target_pid, bool exclude_target);

void set_breakpoint(pid_t tid, uint64_t addr);

void remove_breakpoint(int perf_fd, uint64_t addr);

void sampling_handler(int signum, siginfo_t *info, void *ucontext);

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext);

int perf_events_enable(pid_t tid, pid_t main_tid = -1);
#endif