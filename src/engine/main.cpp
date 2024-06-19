#define _GNU_SOURCE
#include "amed.h"
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
#include <ucontext.h>
#include <unistd.h>
#include <unordered_map>

constexpr int MAX_THREAD_NUM = 200;

// Mapping from fd of perf event to tid
int perf_id_map[MAX_THREAD_NUM]{};

void main_sampling_handler(int signum, siginfo_t *info, void *ucontext)
{
    pid_t tid = perf_id_map[info->si_fd];
    if (pthread_kill(tid, SIGIO) != 0)
    {
        perror("pthread_kill");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("send signal to %d\n", tid);
    }
    disable_perf_sampling(-1, info->si_fd);
}

void first_sampling_handler(int signum, siginfo_t *info, void *ucontext)
{
    printf("First Sampling handler:%d open the real handler\n", syscall(SYS_gettid));
    struct sigaction sa;
    sa.sa_sigaction = sampling_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGIO, &sa, NULL) == -1)
    {
        perror("sigaction");
        return;
    }

    perf_events_enable(syscall(SYS_gettid));
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
        sa.sa_sigaction = first_sampling_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGIO, &sa, NULL) == -1)
        {
            perror("sigaction");
            return;
        }

        // Child process
        // The child process will continue execution as normal, e.g: gaussDB will continue its work
        atexit([]()
               { printf("Just for testing :D Hooked exit function\n"); });

        printf("Child process (PID: %d) continuing with current command.\n", getpid());
    }
    else
    {
        // Profiler process
        printf("Profiler process (PID: %d) executing other logic.\n", getpid());

        std::vector<pid_t> tids = get_tids(pid, true);
        assert(tids.size() > 0 && "Target should has at least one thread.");
        printf("Profiler begin to trace %d\n", tids[0]);

        struct sigaction sa;
        sa.sa_sigaction = first_sampling_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGIO, &sa, NULL) == -1)
        {
            perror("sigaction");
            return;
        }
        int perf_fd = perf_events_enable(tids[0]);
        perf_id_map[perf_fd] = pid;

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