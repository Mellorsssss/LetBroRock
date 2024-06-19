/* This file is used to test the breakpoint utility of perf. */
#define _GNU_SOURCE
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "utils.h"
#include <cassert>
#include <iostream>

void handle_signal(int signum, siginfo_t *info, void *ucontext)
{
  ucontext_t* uc = (ucontext_t*)(ucontext);
  printf("Breakpoint hit at address: %llx\n", (uintptr_t)(uc->uc_mcontext.gregs[REG_RIP]));
  thread_context a;
  user_context b;
  find_next_unresolved_branch((uintptr_t)(uc->uc_mcontext.gregs[REG_RIP]), a, b);
  sleep(1);
}

int fuck = 0;
int shit()
{
  int res = 3;
  if (fuck == 1) {
    res += 1;
  } else {
    res += 2;
  }
  return res;
}
int test()
{
  int shit = 10;
  return shit;
}

void *foo(void *)
{
  for(int i = 0; i< 10; i++){
    fuck += test();
    fuck += shit();
  }
  
  printf("%d\n", fuck);
  return NULL;
}

int main(void)
{
  
  printf("%d\n", getpid());
  {
    struct perf_event_attr pea;
    memset(&pea, 0, sizeof(struct perf_event_attr));
    pea.type = PERF_TYPE_BREAKPOINT;
    pea.size = sizeof(struct perf_event_attr);
    pea.bp_type = HW_BREAKPOINT_X;
    pea.bp_addr = (uintptr_t)(0x5555555faf67); // Change this to the address you want to set the breakpoint at
    std::cout<<(uintptr_t)(&test)<<std::endl;
    pea.bp_len = 8;
    pea.sample_period = 1;
    pea.disabled = 1;
    pea.exclude_kernel = 1;
    pea.exclude_hv = 1;
    pea.exclude_idle = 1;

    printf("expect bp addr: %#lx\n", (uintptr_t)(&test));
    assert( (uintptr_t)(&test) == (uintptr_t)(0x5555555faf40));

    int fd = perf_event_open(&pea, 0, -1, -1, 0);
    if (fd == -1)
    {
      fprintf(stderr, "Error opening leader %llx\n", pea.config);
      perror("perf_event_open");
      exit(EXIT_FAILURE);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = handle_signal;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGIO, &sa, NULL);

    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETSIG, SIGIO);
    fcntl(fd, F_SETFL, O_NONBLOCK | O_ASYNC);

    // open perf_event
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    
    foo(NULL);

    pause();

    close(fd);
  }
  return 0;
}