#ifndef LBR_UTILS
#define LBR_UTILS
#include "amed.h"
#include "consts.h"
#include "decoder.hpp"
#include "log.h"
#include "thread_context.h"

#include <asm/unistd.h>
#include <fcntl.h>
#include <iostream>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <functional>
#include <stack>

typedef struct user_regs_struct user_context;

uint64_t get_pc(ucontext_t *ucontext);

long perf_event_open(struct perf_event_attr *event_attr, pid_t pid, int cpu, int group_fd, unsigned long flags);

bool find_next_branch(ThreadContext &tcontext, uint64_t pc, int length);

std::pair<uint64_t, bool> check_branch_if_taken(ThreadContext &tcontext, ucontext_t &context, bool static_eval,
                                                int length);

std::vector<pid_t> get_tids(pid_t target_pid, const std::vector<pid_t> &exclue_targets, int max_size);

bool is_control_flow_transfer(amed_insn &insn);

// return [target_addr, should make breakpoint]
std::pair<uint64_t, bool> static_evaluate(ThreadContext &tcontext, uint64_t pc, amed_context &context, amed_insn &insn);

// return [target_addr, taken]
std::pair<uint64_t, bool> evaluate(void *dr_context, amed_context &context, amed_insn &insn, ucontext_t *ucontext);

std::pair<uint64_t, bool> evaluate_x86(void *dr_context, amed_context &context, amed_insn &insn, ucontext_t *ucontext);

std::pair<uint64_t, bool> evaluate_arm(void *dr_context, instr_t &d_insn, amed_context &context, amed_insn &insn,
                                       ucontext_t *ucontext);


int tgkill(pid_t group_id, pid_t tid, int signo);

class Deferrer
{
  public:
    Deferrer() {}
    ~Deferrer() { 
      if (!canceled_)
        callAll(); 
    }

    void addCall(std::function<void()> &&func)
    {
      callStack_.push(std::forward<decltype(func)>(func));
    }

    void cancel() { canceled_ = true; }
    
  private:
    std::stack<std::function<void()>> callStack_;
    bool canceled_{false};

    void callAll()
    {
       while(!callStack_.empty())
       {
          callStack_.top()();
          callStack_.pop();
       }
    }
};

// We might want perfect forwarding here, but that's in the TODO list for now
#define defer(...) \
  do { \
    auto deferred = std::bind(__VA_ARGS__); \
    __deferrer.addCall(deferred); \
  } while(0);

#define allow_deferred() \
  Deferrer __deferrer;

#define cancel_deferred() \
  __deferrer.cancel();
#endif