#define _GNU_SOURCE
#include "amed.h"
#include "dr_api.h"
#include "dr_tools.h"
#include "executable_segments.h"
#include "stack_lbr_utils.h"
#include "unwind.h"
#include "utils.h"
#include <bits/siginfo.h>
#include <cassert>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <shared_mutex>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#include <ucontext.h>
#include <unistd.h>
#include <unordered_map>

constexpr int MAX_THREAD_NUM = 200;

thread_local void *thread_dr_context = nullptr;

thread_local int branch_cnt = 0;
thread_local int branch_total_cnt = 0;
thread_local int branch_static_cnt = 0;
thread_local int branch_dyn_cnt = 0;

/* thread state machine
 * When a thread first call sampling_handler, it will set `thread_inited` to true
 * When `state` is BREAKPOINT, thread can't call sampling handler
 */
thread_local bool thread_inited = false;
typedef enum _thread_state
{
    SAMPLING,
    BREAKPOINT,
} thread_state;
thread_local thread_state state = thread_state::SAMPLING;

thread_local uint64_t breakpoint_addr = UNKNOWN_ADDR;

thread_local ThreadUnwind thread_unwind_util;
thread_local StackLBREntry thread_stack_lbr_entry;
thread_local StackLBRBuffer* thread_buffer{nullptr};

// perf_events related data structure
thread_local void *rbuf = nullptr;
struct perf_ip_sample
{
    struct perf_event_header header;
    uint64_t ip;
};

ExecutableSegments *executable_segments = nullptr;

void set_breakpoint(pid_t tid, uint64_t addr);

void remove_breakpoint(int perf_fd, uint64_t addr);

void sampling_handler(int signum, siginfo_t *info, void *ucontext);

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext);

std::pair<branch, bool> find_next_unresolved_branch(uint64_t pc, thread_context &tcontext);

void enable_perf_sampling(pid_t tid)
{
    state = thread_state::SAMPLING;
    perf_events_enable(tid, rbuf);
}

bool stack_lbr_entry_full()
{
    return thread_stack_lbr_entry.is_full();
}

void stack_lbr_entry_reset()
{
    branch_total_cnt += branch_cnt;
    branch_cnt = 0;
    thread_stack_lbr_entry.reset();
}

void add_to_stack_lbr_entry(uint64_t from_addr, uint64_t to_addr)
{
    thread_stack_lbr_entry.add_branch(from_addr, to_addr);
}

void set_stack_size(uint8_t size)
{
    thread_stack_lbr_entry.set_stack_size(size);
}

/**
 * iterate instructions from `pc`.
 * If instruction is not cti, keep iterating;
 * If instruction is cti
 *    If instruction can be evaluated statically(jmp, call), add to stack_lbr_entry
 *    Else return false to set a breakpoint
 * ATTENTION:
 * For the last trace, a breakpoint is set to get the call stack.
 */
bool find_next_unresolved_branch(uint64_t pc, branch &br, thread_context &tcontext)
{
    while (true)
    {
        DEBUG("Branch PC: %#lx", pc);
        auto [temp_br, found] = find_next_branch(tcontext, pc);
        if (!found)
        {
            WARNING("Fail to find a branch until the end of the code from %#lx.", pc);
            return false;
        }

        br = temp_br;
        ucontext_t _{};
        auto [target, taken] = check_branch_if_taken(tcontext, br, _, true);

        // handle the breakpoint since the branch can't be evaluated statically
        if (target == UNKNOWN_ADDR)
        {
            DEBUG("Should set the breakpoint");
            return true;
        }

        // branch is statically taken
        if (taken)
        {
            DEBUG("Branch is taken unconditionally");
            if (stack_lbr_entry_full()) // last trace
            {
                DEBUG("stack lbr entry is full, we set the final breakpoint for the call stack");
                return true;
            }
            else
            {
                add_to_stack_lbr_entry(br.from_addr, target);
            }
        }

        pc = target;
    }

    assert(0 && "never hit");
    return false;
}

void signal_prehandle(sigset_t &new_set, sigset_t &old_set, int sig)
{
    sigfillset(&new_set);
    if (pthread_sigmask(SIG_BLOCK, &new_set, &old_set) < 0)
    {
        perror("pthread_sigmask");
        exit(EXIT_FAILURE);
    }
}

void signal_posthandle(sigset_t &old_set)
{
    if (sigprocmask(SIG_SETMASK, &old_set, NULL) < 0)
    {
        perror("pthread_sigmask");
        exit(EXIT_FAILURE);
    }
}

void set_breakpoint(pid_t tid, uint64_t addr)
{
    state = thread_state::BREAKPOINT;
    struct perf_event_attr pe;

    breakpoint_addr = addr;
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
    DEBUG("enter the set breakpoint, errno is %d", errno);
    while ((perf_fd = syscall(__NR_perf_event_open, &pe, tid, -1, -1, 0)) == -1)
    {
        perror("perf_event_open");
        WARNING("breakpoint is in use");
        exit(EXIT_FAILURE);
        sched_yield();
    }

    // signal(SIGIO, SIG_DFL);
    struct f_owner_ex owner;
    owner.type = F_OWNER_TID;
    owner.pid = tid;

    if (fcntl(perf_fd, F_SETOWN_EX, &owner) == -1)
    {
        perror("F_SETSIG");
        exit(EXIT_FAILURE);
    }

    if (fcntl(perf_fd, F_SETSIG, SIGTRAP) == -1)
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

    DEBUG("successfully set breakpoint at %lx", pe.bp_addr);
    if (ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0) != 0)
    {
        perror("PERF_EVENT_IOC_RESET");
        exit(EXIT_FAILURE);
    }

    if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) != 0)
    {
        perror("PERF_EVENT_IOC_ENABLE");
        exit(EXIT_FAILURE);
    }
}

void remove_breakpoint(int perf_fd, uint64_t addr)
{
    // TODO: maybe this method could be replaced with disable_perf_sampling
    DEBUG("successfully remove breakpoint at %#lx of %d", addr, perf_fd);
    if (close(perf_fd) != 0)
    {
        perror("close");
        exit(EXIT_FAILURE);
    }
}

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext)
{
    print_backtrace();

    assert(errno != EINTR && "breakpoint should not hit the syscall");
    sigset_t new_set, old_set;
    signal_prehandle(new_set, old_set, SIGIO);

    // we should disable the breakpoint at the immediately
    ucontext_t *uc = (ucontext_t *)ucontext;
    uint64_t pc = get_pc(uc);

    remove_breakpoint(info->si_fd, pc);
    if (pc != breakpoint_addr || !executable_segments->isAddressInExecutableSegment(pc))
    {
        ERROR("real breakpoint %#lx is different from setted breakpoint addr %#lx", pc, breakpoint_addr);
        enable_perf_sampling(syscall(SYS_gettid));
        signal_posthandle(old_set);

        return;
    }
    breakpoint_addr = UNKNOWN_ADDR;

    DEBUG("Breakpoint handler: the fd is %d handled by %d", info->si_fd, syscall(SYS_gettid));

    branch br = branch{.from_addr = pc};
    thread_context tcontext{
        .tid = (pid_t)syscall(SYS_gettid),
        .dr_context = thread_dr_context,
    };

    auto [target, taken] = check_branch_if_taken(tcontext, br, *uc, false);
    if (taken)
    {
        if (stack_lbr_entry_full())
        {
            WARNING("call stack sample check point");
            thread_unwind_util.reset();

            uint8_t real_frame_size;
            if (!thread_unwind_util.unwind((siginfo_t *)info, ucontext, thread_stack_lbr_entry.get_stack_buffer(), MAX_FRAME_SIZE, real_frame_size))
            {
                ERROR("fail to get the call stack");
            }

            thread_stack_lbr_entry.set_stack_size(real_frame_size);

            stack_lbr_entry_reset();

            enable_perf_sampling(tcontext.tid);
            signal_posthandle(old_set);

            return;
        }
        else
        {
            add_to_stack_lbr_entry(pc, target);
        }
    }

    bool ok = find_next_unresolved_branch(target, br, tcontext);

    if (!executable_segments->isAddressInExecutableSegment(br.from_addr))
    {
        ERROR("breakpoint handler triggered at un-executable pc %lx", br.from_addr);
    }
    if (ok)
    {
        signal_posthandle(old_set);
        set_breakpoint(tcontext.tid, br.from_addr);
    }
    else
    {
        enable_perf_sampling(tcontext.tid);
        signal_posthandle(old_set);
    }

    return;
}

void sampling_handler(int signum, siginfo_t *info, void *ucontext)
{
    if (state != thread_state::SAMPLING)
    {
        WARNING("redudant sampling handler(probably from previous fd), just return");
        return;
    }

    print_backtrace();
    if (!thread_inited)
    {
        // init the thread_stack_lbr_entry
        stack_lbr_entry_reset();

        // init the dr_context
        thread_dr_context = dr_standalone_init();
#if defined(__x86_64__)
        if (!dr_set_isa_mode(thread_dr_context, DR_ISA_AMD64, nullptr))
#elif defined(__aarch64__)
        if (!dr_set_isa_mode(thread_dr_context, DR_ISA_ARM_A64, nullptr))
#endif
        {
            ERROR("fail to set the isa mode.");
        }
        thread_inited = true;

        // temporarily mmap the rbuf
        rbuf = mmap(NULL, get_mmap_len(), PROT_READ, MAP_SHARED, info->si_fd, 0);
        if (rbuf == MAP_FAILED)
        {
            perror("mmap");
            ERROR("fail to mmap");
        }
    }
    pid_t target_pid = syscall(SYS_gettid);

    long long count;
    if (read(info->si_fd, &count, sizeof(long long)) > 0)
    {
        // ERROR("the count %d", count);
        // ERROR("read error:%d", info->si_fd)void*;
    }

    disable_perf_sampling(target_pid, info->si_fd);

    // trick: if sampling handler interrupt a syscall, we just simply return
    if (errno == EINTR)
    {
        errno = 0;
        WARNING("Sampling handler mitakenly interrupt a syscall, just return");
        munmap(rbuf, get_mmap_len());
        return;
    }

    sigset_t new_set, old_set;
    signal_prehandle(new_set, old_set, SIGIO);

    ucontext_t *uc = (ucontext_t *)ucontext;

    DEBUG("Sampling handler: the fd is %d, handled by %d", info->si_fd, syscall(SYS_gettid));

    // get PC
    uint64_t pc = get_pc(uc);
    uint64_t offset = sysconf(_SC_PAGESIZE);
    DEBUG("Sampling handler: try to read the buf");

    if (rbuf == nullptr)
    {
        ERROR("fail to read from nullptr buffer");
    }

    perf_ip_sample *sample = (perf_ip_sample *)((uint8_t *)rbuf + offset);
    DEBUG("Sampling handler: try to get the ip");
    if (sample->header.type == PERF_RECORD_SAMPLE)
    {
        WARNING("the ip is %#lx sampled from %#lx\n", sample->ip, pc);
    }
    else
    {
        ERROR("we should get a perf record sample here");
    }
    DEBUG("Sampling handler: get the ip");

    pc = sample->ip;
    if (!executable_segments->isAddressInExecutableSegment(pc))
    {
        ERROR("Sampling handler triggered at un-executable pc %lx", pc);
        enable_perf_sampling(target_pid);
        signal_posthandle(old_set);
        munmap(rbuf, get_mmap_len());
        return;
    }

    thread_context tcontext{
        .tid = target_pid,
        .dr_context = thread_dr_context,
    };

    branch br;
    bool ok = find_next_unresolved_branch(pc, br, tcontext);
    if (ok)
    {
        signal_posthandle(old_set);
        set_breakpoint(target_pid, br.from_addr);
    }
    else
    {
        enable_perf_sampling(target_pid);
        signal_posthandle(old_set);
    }

    munmap(rbuf, get_mmap_len());
}

std::vector<pid_t> start_profiler(pid_t pid, pid_t tid)
{
    std::vector<pid_t> tids = get_tids(pid, tid);
    assert(tids.size() > 0 && "Target should has at least one thread.");
    WARNING("main :%d and current %d", pid, tid);

    for (auto &tid : tids)
    {
        WARNING("try to enable perf events for %d", tid);
        void *_;
        perf_events_enable(tid, _);
    }

    return tids;
}

void stop_profiler()
{
    // TODO
}

void app_thread_exit_work()
{
    // TODO
}

/* main thread is designed to :
 * 1. spawn writer thread for writing output file
 * 2. periodically call start_profiler and stop_profiler
 */
void profiler_main_thread()
{
    pid_t pid = getpid();
    pid_t tid = syscall(SYS_gettid);

    sigset_t new_set, old_set;
    signal_prehandle(new_set, old_set, SIGTRAP);

    // usleep(1000); // sleep for 100 ms before the first start
    while (true)
    {
        auto tids = start_profiler(pid, tid);

        stop_profiler();
        return;
        // usleep(1000 * 1000000000000); // sleep for 100 ms
    }

    return;
}

__attribute__((constructor)) void preload_main()
{
    executable_segments = new ExecutableSegments(true);

    // register handler of SIGIO for all threads
    struct sigaction sa;
    sa.sa_sigaction = sampling_handler;
    sa.sa_flags = SA_SIGINFO; // | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGIO, &sa, NULL) == -1)
    {
        perror("sigaction");
        return;
    }

    // register handler of SIGTRAP for all threads
    sa.sa_sigaction = breakpoint_handler;
    sa.sa_flags = SA_SIGINFO; // | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, NULL) == -1)
    {
        perror("sigaction");
        return;
    }
    std::thread t(profiler_main_thread);
    t.detach(); // TODO: it seems a little dangerous

    atexit([]()
           { 
                app_thread_exit_work();
                dr_standalone_exit();
                ERROR("the thread %d records %d(%d, %d) branches.", syscall(SYS_gettid), branch_total_cnt, branch_static_cnt, branch_dyn_cnt);
                INFO("Just for testing :D Hooked exit function"); });
}