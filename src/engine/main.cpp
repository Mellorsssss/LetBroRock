#define _GNU_SOURCE
#include "amed.h"
#include "dr_api.h"
#include "dr_tools.h"
#include "utils.h"
#include <Logger.h>
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
#include <ucontext.h>
#include <unistd.h>
#include <unordered_map>

constexpr int MAX_THREAD_NUM = 200;
constexpr int MAX_LBR_SIZE = 16;

thread_local void *thread_dr_context = nullptr;

thread_local int branch_cnt = 0;

// Mapping from fd of perf event to tid
int perf_id_map[MAX_THREAD_NUM]{};

void set_breakpoint(pid_t tid, uint64_t addr);

void remove_breakpoint(int perf_fd, uint64_t addr);

void sampling_handler(int signum, siginfo_t *info, void *ucontext);

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext);

std::pair<branch, bool> find_next_unresolved_branch(uint64_t pc, thread_context &tcontext);

bool buffer_size()
{
    return MAX_LBR_SIZE - branch_cnt;
}

bool buffer_full()
{
    return MAX_LBR_SIZE == branch_cnt;
}

void buffer_reset()
{
    branch_cnt = 0;
}

bool find_next_unresolved_branch(uint64_t pc, branch &br, thread_context &tcontext)
{
    while (true)
    {
        printf("find_next_unresolved_branch: Branch PC: %#lx\n", pc);
        auto res = find_next_branch(tcontext, pc);
        if (!res.second)
        {
            printf("find_next_unresolved_branch: Fail to find a branch until the end of the code.\n");
            return false;
        }
        else
        {
            br = res.first;

            // handle the breakpoint
            if (br.to_addr == UNKNOWN_ADDR)
            {
                LogInfo("find_next_unresolved_branch: Should set the breakpoint\n");
                return true;
            }

            LogInfo("find_next_unresolved_branch: Branch is taken unconditionally");
            if (buffer_size() == 0)
            {
                return false;
            }
            else
            {
                branch_cnt++;
            }

            pc = br.to_addr;
        }
    }

    assert(0 && "find_next_unresolved_branch: never hit");
    return false;
}

void signal_prehandle(sigset_t &new_set, sigset_t &old_set)
{
    // return;
    sigfillset(&new_set); // 设置new_set为包含所有信号
    if (sigprocmask(SIG_BLOCK, &new_set, &old_set) < 0)
    {
        perror("sigprocmask");
        exit(EXIT_FAILURE);
    }
}

void signal_posthandle(sigset_t &old_set)
{
    // return;
    if (sigprocmask(SIG_SETMASK, &old_set, NULL) < 0)
    {
        perror("sigprocmask");
        exit(EXIT_FAILURE);
    }
}

void bootstrap_sampling_handler(int signum, siginfo_t *info, void *ucontext)
{
    printf("First Sampling handler:%d open the real handler at %#lx\n", syscall(SYS_gettid), get_pc((ucontext_t *)ucontext));
    struct sigaction sa;
    sa.sa_sigaction = sampling_handler;
    // sa.sa_flags = SA_SIGINFO | SA_ONESHOT | SA_RESTART;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGIO, &sa, NULL) == -1)
    {
        perror("sigaction");
        return;
    }

    // init the dr_context
    thread_dr_context = dr_standalone_init();
    if (!dr_set_isa_mode(thread_dr_context, DR_ISA_AMD64, nullptr))
    {
        printf("fail to set the isa mode.\n");
        exit(EXIT_FAILURE);
    }

    perf_events_enable(syscall(SYS_gettid));
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

    // reset the signal handler
    struct sigaction sa;
    sa.sa_sigaction = breakpoint_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONESHOT | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, NULL) == -1)
    {
        perror("sigaction");
        return;
    }

    printf("successfully set breakpoint at %lx\n", pe.bp_addr);
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
    if (close(perf_fd) != 0)
    {
        perror("close");
        exit(EXIT_FAILURE);
    }

    // reset the signal handler
    struct sigaction sa;
    sa.sa_sigaction = sampling_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONESHOT | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGIO, &sa, NULL) == -1)
    {
        perror("sigaction");
        return;
    }

    printf("successfully remove breakpoint at %#lx of %d\n", addr, perf_fd);
}

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext)
{
    assert(errno != EINTR && "breakpoint should not hit the syscall");
    sigset_t new_set, old_set;
    signal_prehandle(new_set, old_set);

    // we should disable the breakpoint at the immediately
    ucontext_t *uc = (ucontext_t *)ucontext;
    uint64_t pc = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    remove_breakpoint(info->si_fd, pc);

    printf("si_code:%d\n", info->si_code);
    printf("Breakpoint handler: the fd is %d handled by %d\n", info->si_fd, syscall(SYS_gettid));

    branch br = branch{.from_addr = pc};
    thread_context tcontext{
        .tid = (pid_t)syscall(SYS_gettid),
        .dr_context = thread_dr_context,
    };

    std::pair<uint64_t, bool> target_taken = record_branch_if_taken(tcontext, br, *uc);
    if (target_taken.second)
    {
        if (buffer_size() == 0)
        {
            buffer_reset();
            perf_events_enable(tcontext.tid);
            signal_posthandle(old_set);
            return;
        }
        else
        {
            branch_cnt++;
        }
    }

    bool ok = find_next_unresolved_branch(target_taken.first, br, tcontext);
    if (ok)
    {
        set_breakpoint(tcontext.tid, br.from_addr);
        signal_posthandle(old_set);
    }
    else
    {
        perf_events_enable(tcontext.tid);
        signal_posthandle(old_set);
    }

    return;
}

void sampling_handler(int signum, siginfo_t *info, void *ucontext)
{
    // trick: if sampling handler interrupt a syscall, we just simply return
    if (errno == EINTR)
    {
        errno = 0;
        printf("Sampling handler mitakenly interrupt a syscall, just return\n");
        return;
    }
    pid_t target_pid = syscall(SYS_gettid);
    disable_perf_sampling(target_pid, info->si_fd);

    sigset_t new_set, old_set;
    signal_prehandle(new_set, old_set);

    ucontext_t *uc = (ucontext_t *)ucontext;

    printf("Sampling handler: the fd is %d, handled by %d\n", info->si_fd, syscall(SYS_gettid));

    // get PC
    uint64_t pc = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    printf("ip: %lx\n", pc);

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
        signal_posthandle(old_set);
        perf_events_enable(target_pid);
    }
}

__attribute__((constructor)) void preload_main()
{
    pid_t pid = fork();

    if (pid < 0)
    {
        // Fork failed
        perror("Profiler failed to fork >:|");
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
        // register handler of SIGIO for all threads
        struct sigaction sa;
        sa.sa_sigaction = bootstrap_sampling_handler;
        sa.sa_flags = SA_SIGINFO | SA_ONESHOT | SA_RESTART;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGIO, &sa, NULL) == -1)
        {
            perror("sigaction");
            return;
        }

        // Child process
        // The child process will continue execution as normal, e.g: gaussDB will continue its work
        atexit([]()
               { 
                dr_standalone_exit();
                printf("Just for testing :D Hooked exit function\n"); });

        printf("Child process (PID: %d) continuing with current command.\n", getpid());
    }
    else
    {
        // Profiler process
        printf("Profiler process (PID: %d) executing other logic.\n", getpid());

        std::vector<pid_t> tids = get_tids(pid, false);
        assert(tids.size() > 0 && "Target should has at least one thread.");
        printf("Profiler begin to trace %d\n", tids[0]);

        for (auto &tid : tids)
        {
            if (kill(tid, SIGIO) != 0)
            {
                perror("pthread_kill");
                exit(EXIT_FAILURE);
            }
        }

        while (1)
        {
            pause();
        }

        int status;
        waitpid(tids[0], &status, __WALL);
        if (errno != 0)
        {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }

        if (WIFEXITED(status))
        {
            printf("Child process exited with status %d.\n", WEXITSTATUS(status));
        }
        else
        {
            printf("Child process did not exit normally.\n");
        }

        // Optionally, exit the parent process if it's not needed
        exit(EXIT_SUCCESS);
    }
}