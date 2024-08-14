#define _GNU_SOURCE
#include "amed.h"
#include "executable_segments.h"
#include "buffer_manager.h"
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
#include <chrono>

constexpr int MAX_THREAD_NUM = 2;

#define SIGBEGIN (SIGRTMIN + 1)
#define SIGEND (SIGBEGIN + 1)

thread_local ThreadContext thread_local_context;
ExecutableSegments *executable_segments = nullptr;
BufferManager* buffer_manager = nullptr;

void construct_handler(int signum, siginfo_t *info, void *ucontext);

void destruct_handler(int signum, siginfo_t *info, void *ucontext);

void sampling_handler(int signum, siginfo_t *info, void *ucontext);

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext);

bool find_next_unresolved_branch(ThreadContext &tcontext, uint64_t pc);

void signal_prehandle(sigset_t &new_set, sigset_t &old_set);

void signal_posthandle(sigset_t &old_set);

// use RAII to auto block/unblock signals
class SignalGuard{
public:
    SignalGuard() {
        signal_prehandle(new_set, old_set);
    }

    ~SignalGuard() {
        signal_posthandle(old_set);
    }
private:
    sigset_t new_set;
    sigset_t old_set;
};

class TimerGuard
{
public:
    TimerGuard(const std::string& name)
        :name_(name), start_(std::chrono::high_resolution_clock::now())
    {
    }

    ~TimerGuard()
    {
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start_;
        INFO("%s took %.2f ms", name_.c_str(), elapsed.count());
    }

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> start_;
    std::string name_;
};

/**
 * iterate instructions from `pc`.
 * If instruction is not cti, keep iterating;
 * If instruction is cti
 *    If instruction can be evaluated statically(jmp, call), add to stack_lbr_entry
 *    Else return false to set a breakpoint
 * ATTENTION:
 * For the last trace, a breakpoint is set to get the call stack.
 */
bool find_next_unresolved_branch(ThreadContext &tcontext, uint64_t pc)
{
    while (true)
    {
        //  ERROR("Branch PC: %#lx", pc);
        int length = executable_segments->getExecutableSegmentSize(pc);
        // length=2;
        bool found = find_next_branch(tcontext, pc,length);
        if (!found)
        {
            WARNING("Fail to find a branch until the end of the code from %#lx.", pc);
            return false;
        }

        ucontext_t _{}; // for statical evaluation, ucontext is unnecessary
        auto [target, taken] = check_branch_if_taken(tcontext, _, true);

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
            if (tcontext.stack_lbr_entry_full()) // last trace
            {
                DEBUG("stack lbr entry is full, we set the final breakpoint for the call stack");
                return true;
            }
            else
            {
                tcontext.set_to_addr(target);
                tcontext.add_to_stack_lbr_entry();
            }
        }

        pc = target;
    }

    assert(0 && "never hit");
    return false;
}

void signal_prehandle(sigset_t &new_set, sigset_t &old_set)
{
    sigfillset(&new_set);
    if (pthread_sigmask(SIG_BLOCK, &new_set, &old_set) < 0)
    {
        non_perror("pthread_sigmask");
        exit(EXIT_FAILURE);
    }
}

void signal_posthandle(sigset_t &old_set)
{
    if (pthread_sigmask(SIG_SETMASK, &old_set, NULL) < 0)
    {
        non_perror("pthread_sigmask");
        exit(EXIT_FAILURE);
    }
}

void construct_handler(int signum, siginfo_t *info, void *ucontext)
{
    DEBUG("construct_handler call in %d", thread_local_context.get_tid());
   
    thread_local_context.set_buffer_manager(buffer_manager);
    thread_local_context.open_perf_sampling_event();
}

void destruct_handler(int signum, siginfo_t *info, void *ucontext)
{
    DEBUG("destruct_handler call in %d", thread_local_context.get_tid());
    thread_local_context.destroy();
}

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext)
{
    if (errno != 0) {
        ERROR("invalid errno %d", errno);
        // drop the data collected in the current stack_lbr_entry
        thread_local_context.reset_entry();
        thread_local_context.close_perf_breakpoint_event();
        thread_local_context.enable_perf_sampling_event();
        return;
    }

    assert(errno != EINTR && "breakpoint should not hit the syscall");
    assert(thread_local_context.get_tid() == syscall(SYS_gettid) && "thread_local_context with wrong tid");

    /**
     * preconditions:
     * 1. thread is in breakpoint mode
     * 2. fd triggering event is bp_fd_
     * 3. address triggering event is bp_addr_
     * 4. address triggering event must be br.from_addr
     */
    if (!thread_local_context.is_breakpointing())
    {
        ERROR("breakpoint hit when the thread is not in breakpoint");
        thread_local_context.close_perf_breakpoint_event();
        thread_local_context.reset_entry();
        thread_local_context.enable_perf_sampling_event();
        return;
    }

    if (thread_local_context.get_breakpoint_fd() != info->si_fd)
    {
        ERROR("breakpoint hit with wrong fd:%d(expected %d)", info->si_fd, thread_local_context.get_breakpoint_fd());
        thread_local_context.close_perf_breakpoint_event();
        thread_local_context.reset_entry();
        thread_local_context.enable_perf_sampling_event();
        return;
    }

    uint64_t bp_addr = thread_local_context.get_breakpoint_addr();
    ucontext_t *uc = (ucontext_t *)ucontext;
    uint64_t pc = get_pc(uc);

    if (pc != bp_addr || bp_addr != thread_local_context.get_branch().from_addr || !executable_segments->isAddressInExecutableSegment(pc))
    {
        ERROR("real breakpoint %#lx is different from setted breakpoint addr %#lx", pc, bp_addr);
        thread_local_context.close_perf_breakpoint_event();
        thread_local_context.reset_entry();
        thread_local_context.enable_perf_sampling_event();
        return;
    }

    // we should disable the breakpoint at the immediately
    thread_local_context.close_perf_breakpoint_event();

    DEBUG("Breakpoint handler: the fd is %d handled by %d", info->si_fd, thread_local_context.get_tid());

    auto [target, taken] = check_branch_if_taken(thread_local_context, *uc, false);
    if (taken)
    {
        if (thread_local_context.stack_lbr_entry_full())
        {
            INFO("%d call stack sample check point", thread_local_context.get_tid());

            thread_local_context.reset_unwind();
            uint8_t real_frame_size;
            if (!thread_local_context.unwind((siginfo_t *)info, ucontext, thread_local_context.get_entry()->get_stack_buffer(), MAX_FRAME_SIZE, real_frame_size))
            {
                ERROR("%d fail to get the call stack", thread_local_context.get_tid());
            }

            thread_local_context.get_entry()->set_stack_size(real_frame_size);
            thread_local_context.reset();
            INFO("%d unwind %d stack frames", thread_local_context.get_tid(), real_frame_size);

            thread_local_context.enable_perf_sampling_event();
            return;
        }
        else
        {
            thread_local_context.set_to_addr(target);
            thread_local_context.add_to_stack_lbr_entry();
        }
    }

    bool ok = find_next_unresolved_branch(thread_local_context, target);

    uint64_t next_from_addr = thread_local_context.get_branch().from_addr;
    if (!executable_segments->isAddressInExecutableSegment(next_from_addr))
    {
        ERROR("breakpoint handler triggered at un-executable pc %lx", next_from_addr);
        thread_local_context.reset_entry();
        thread_local_context.enable_perf_sampling_event();
        return;
    }

    if (ok)
    {
        thread_local_context.open_perf_breakpoint_event(next_from_addr);
    }
    else
    {
        thread_local_context.enable_perf_sampling_event();
    }

    return;
}

void sampling_handler(int signum, siginfo_t *info, void *ucontext)
{
    thread_local_context.disable_perf_sampling_event();
    if (errno != 0)
    {
        ERROR("thread %d Sampling handler mitakenly interrupt a syscall(%d, fd: %d), just return", thread_local_context.get_tid(), errno, info->si_fd);
        thread_local_context.enable_perf_sampling_event();
        return;
    }

    /**
     * preconditions:
     * 1. thread is in sampling mode
     * 2. fd triggering event is sampling_fd_
     */
    if (!thread_local_context.is_sampling())
    {
        ERROR("thread %d redudant sampling handler(probably from previous fd:%d), just return", thread_local_context.get_tid(), info->si_fd);
        thread_local_context.enable_perf_sampling_event();
        return;
    }

    if (thread_local_context.get_sampling_fd() != info->si_fd)
    {
        ERROR("thread %d sampling hit with wrong fd:%d(expected %d)", thread_local_context.get_tid(), info->si_fd, thread_local_context.get_sampling_fd());
        thread_local_context.enable_perf_sampling_event();
        return;
    }

    INFO("%d reset the entry", thread_local_context.get_tid());
    thread_local_context.reset_entry();
    // thread_local_context.reset_branch();

    pid_t target_pid = syscall(SYS_gettid);


    ucontext_t *uc = (ucontext_t *)ucontext;

    DEBUG("Sampling handler: the fd is %d, handled by %d", info->si_fd, syscall(SYS_gettid));

    // get PC
    uint64_t pc = get_pc(uc);

    if (!executable_segments->isAddressInExecutableSegment(pc))
    {
        ERROR("Sampling handler triggered at un-executable pc %lx", pc);
        thread_local_context.enable_perf_sampling_event();
        return;
    }

    bool ok = find_next_unresolved_branch(thread_local_context, pc);
    if (ok)
    {
        thread_local_context.open_perf_breakpoint_event(thread_local_context.get_branch().from_addr);
    }
    else
    {
        thread_local_context.enable_perf_sampling_event();
    }
}

std::vector<pid_t> start_profiler(pid_t pid, pid_t tid)
{
    TimerGuard timer_guard("start profiler");
    std::vector<pid_t> tids = get_tids(pid, std::vector<pid_t>{tid, pid}, MAX_THREAD_NUM);

    assert(tids.size() > 0 && "Target should has at least one thread.");
    INFO("main :%d and current %d", pid, tid);

    for (auto &tid : tids)
    {
        INFO("begin to start %d", tid);
        if (tgkill(pid, tid, SIGBEGIN) != 0)
        {
            ERROR("fail to begin %d", tid);
        }
    }

    // Attention: we must start the writer thread after the calling of get_tids
    buffer_manager->start_writer_thread();
    return tids;
}

void stop_profiler(pid_t pid, std::vector<pid_t> &tids)
{
    TimerGuard timer_guard("stop profiler");
    for (auto &tid : tids)
    {
        INFO("begin to stop %d", tid);
        if (tgkill(pid, tid, SIGEND) != 0)
        {
            ERROR("fail to end %d", tid);
        }
    }

    // Attention: we must stop the writer thread explicitly
    buffer_manager->stop_writer_thread();
}

/* main thread is designed to :
 * 1. spawn writer thread for writing output file
 * 2. periodically call start_profiler and stop_profiler
 */
void profiler_main_thread()
{
    pid_t pid = getpid();
    pid_t tid = syscall(SYS_gettid);
    buffer_manager->malloc_all_buffers();
    while (true)
    {   
        // buffer_manager->malloc_all_buffers();
        auto tids = start_profiler(pid, tid);
        std::this_thread::sleep_for(std::chrono::milliseconds(4000));
        INFO("restart the profiler");
        stop_profiler(pid, tids);
        // buffer_manager->delete_all_buffers();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    buffer_manager->delete_all_buffers();
    delete buffer_manager;
    return;
}

__attribute__((constructor)) void preload_main()
{
    INFO("begin");
    executable_segments = new ExecutableSegments(true);
    buffer_manager = new BufferManager(MAX_THREAD_NUM, "perf_data.lbr"); 
    initLogFile();

    // register handler of SIGBEGIN for all threads
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = construct_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigfillset(&sa.sa_mask);
        if (sigaction(SIGBEGIN, &sa, NULL) != 0)
        {
            non_perror("sigaction");
            return;
        }
    }

    // register handler of SIGEND for all threads
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = destruct_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigfillset(&sa.sa_mask);
        if (sigaction(SIGEND, &sa, NULL) != 0)
        {
            non_perror("sigaction");
            return;
        }
    }

    // register handler of SIGIO for all threads
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = sampling_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigfillset(&sa.sa_mask);
        if (sigaction(SIGIO, &sa, NULL) != 0)
        {
            non_perror("sigaction");
            return;
        }
    }

    // register handler of SIGTRAP for all threads
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = breakpoint_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigfillset(&sa.sa_mask);
        if (sigaction(SIGRTMIN+4, &sa, NULL) != 0)
        {
            non_perror("sigaction");
            return;
        }
    }
    std::thread t(profiler_main_thread);
    t.detach();

    atexit([]()
           { 
                INFO("Just for testing :D Hooked exit function"); });
}