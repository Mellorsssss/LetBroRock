#ifndef LBR_UTILS
#define LBR_UTILS
#include "amed.h"
#include "decoder.hpp"
#include <asm/unistd.h>
#include <fcntl.h>
#include <iostream>
#include <linux/perf_event.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <stdio.h>
#include <stdarg.h>

typedef enum
{
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LogLevel;

#define COLOR_RESET "\x1b[0m"
#define COLOR_DEBUG "\x1b[34m"
#define COLOR_INFO "\x1b[32m"
#define COLOR_WARNING "\x1b[33m"
#define COLOR_ERROR "\x1b[31m"

void logMessage(LogLevel level, const char *file, int line, const char *format, ...);

#define LOG(level, ...) logMessage(level, __FILE__, __LINE__, __VA_ARGS__)

#define DEBUG(...) LOG(LOG_DEBUG, __VA_ARGS__)
#define INFO(...) LOG(LOG_INFO, __VA_ARGS__)
#define WARNING(...) LOG(LOG_WARNING, __VA_ARGS__)
#define ERROR(...) LOG(LOG_ERROR, __VA_ARGS__)

typedef struct _branch
{
    uintptr_t from_addr;
    uintptr_t to_addr;
} branch;

typedef struct _thread_context
{
    pid_t tid;
    void *dr_context;
} thread_context;

typedef struct user_regs_struct user_context;
const uint64_t UNKNOWN_ADDR = 0;
const uint64_t RINGBUFFER_SIZE = 16;

uint64_t get_mmap_len();

uint64_t get_pc(ucontext_t *ucontext);

long perf_event_open(struct perf_event_attr *event_attr, pid_t pid, int cpu,
                     int group_fd, unsigned long flags);

bool find_next_unresolved_branch(uint64_t pc, branch &br, thread_context &tcontext);

std::pair<branch, bool> find_next_branch(thread_context &tcontext, uint64_t pc);

void disable_perf_sampling(pid_t tid, int perf_fd);

void enable_perf_sampling(pid_t tid, int perf_fd);

std::pair<uint64_t, bool> record_branch_if_taken(thread_context &tcontext, branch &br, ucontext_t &context);

std::vector<pid_t> get_tids(pid_t target_pid, pid_t exclue_target);

int perf_events_enable(pid_t tid, void *&buf);

bool is_control_flow_transfer(amed_insn &insn);

// return [target_addr, should make breakpoint]
std::pair<uint64_t, bool> static_evaluate(thread_context &tcontext, uint64_t pc, amed_context &context, amed_insn &insn);

// return [target_addr, taken]
std::pair<uint64_t, bool> evaluate(void *dr_context, amed_context &context, amed_insn &insn, ucontext_t *ucontext);

std::pair<uint64_t, bool> evaluate_x86(void *dr_context, amed_context &context, amed_insn &insn, ucontext_t *ucontext);

std::pair<uint64_t, bool> evaluate_arm(void *dr_context, amed_context &context, amed_insn &insn, ucontext_t *ucontext);

void print_backtrace();
#endif