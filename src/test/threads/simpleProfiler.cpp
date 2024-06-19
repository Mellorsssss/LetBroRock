#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/perf_event.h>
#include <pthread.h>
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
#include <unistd.h>
#include <bits/siginfo.h>
#include <ucontext.h>

int perf_fd;
pid_t monitored_tid;
volatile bool has_trace = false;
void signal_handler(int signum, siginfo_t* info, void* ucontext)
{
    // TODO: it seems the si_code is always the POLL_IN
    // if(info->si_code != POLL_HUP) {
        // Only POLL_HUP should happen.
        // exit(EXIT_FAILURE);
    // }

    printf("the signo is %d\n", signum);
    printf("the id is %d, and perf_fd is %d\n", info->si_fd, perf_fd);
    printf("Sampling counter overflow detected\n");
    if (ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
        perror("ioctl(PERF_EVENT_IOC_DISABLE)");
        exit(EXIT_FAILURE);
    }
    

    if (syscall(SYS_gettid) == monitored_tid)
    {
        perror("signal is handled from the monitered therad!!!\n");
    }
    else
    {
        printf("right signal: %d\n", monitored_tid);
    }

    // pause the monitered thread
    if (!has_trace)
    {
        printf("Begin to attch...\n");
        if (ptrace(PTRACE_ATTACH, monitored_tid, NULL, NULL) == 0)
        {
            int status;
            waitpid(monitored_tid, &status, 0);
            printf("the status of monitered thread is %d\n", status);
            
            has_trace = true;
        }
        else
        {
            perror("ATTCH fuck");
        }
    }

    // get PC
    struct user_regs_struct regs;
    int res;
    res = ptrace(PTRACE_GETREGS, monitored_tid, NULL, &regs);
    printf("Thread 2 stopped at RIP: 0x%llx\n", regs.rip);
    printf("the res of GETREGS is %d\n", res);
    sleep(1);

    int status;
    // res = ptrace(PTRACE_CONT, monitored_tid, NULL, NULL);
    // printf("the res of CONT is %d\n", res);

    // waitpid(monitored_tid, &status, 0);
    // printf("the status of monitered thread is %d\n", status);
    res = ptrace(PTRACE_DETACH, monitored_tid, NULL, NULL);
    waitpid(monitored_tid, &status, 0);
    printf("the res of DETACH is %d\n", res);
    printf("the status of monitered thread is %d\n", status);
    has_trace = false;

    if (ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
        perror("ioctl(PERF_EVENT_IOC_DISABLE)");
        exit(EXIT_FAILURE);
    }

    if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) == -1) {
        perror("ioctl(PERF_EVENT_IOC_ENABLE)");
        exit(EXIT_FAILURE);
    }
}

void *monitor_thread(void *arg)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGIO);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

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

    perf_fd = syscall(__NR_perf_event_open, &pe, monitored_tid, -1, -1, 0);
    if (perf_fd == -1)
    {
        perror("perf_event_open");
        return NULL;
    }

    // unblock the SIGIO
    struct sigaction sa;
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO; 
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGIO, &sa, NULL) == -1)
    {
        perror("sigaction");
        return NULL;
    }

    fcntl(perf_fd, F_SETOWN, getpid());
    fcntl(perf_fd, F_SETSIG, SIGIO);
    fcntl(perf_fd, F_SETFL, O_NONBLOCK|O_ASYNC);
    // fcntl(perf_fd, F_SETFL, fcntl(perf_fd, F_GETFL) | O_ASYNC);

    // open perf_event
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

    // wait for the signal
    while (1)
    {
        pause();
    }

    close(perf_fd);
    return NULL;
}

int main(int argc, char **argv)
{
    monitored_tid = atoi(argv[1]);
    printf("The moniterd thread id is %d\n", monitored_tid);

    pthread_t t1;

    // block the signal SIGIO
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGIO);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    pthread_create(&t1, NULL, monitor_thread, NULL);

    pthread_join(t1, NULL);

    return 0;
}