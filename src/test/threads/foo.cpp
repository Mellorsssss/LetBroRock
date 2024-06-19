#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <errno.h>
#include <algorithm>

const int NUM_THREADS = 4;
pid_t child_tid;
char chs[NUM_THREADS];
void* child_thread(void* arg) {
    child_tid = syscall(SYS_gettid);
    char ch = *(char*)arg;
    printf("Child Thread: %d\n", child_tid);
    // sleep to wait for the profiler executing
    // sleep(5);
    int cnt = 0;
    int foo = 3; 
    while (1) {
        if (cnt % 2) {
            //printf(" ");
            cnt += 2;
        } else {
            //printf("%c", ch);
            cnt -=1;
        }
        cnt++;
        // asm volatile("" ::: "memory");
        // usleep(1000);
    }
    printf("%d", cnt);
    return NULL;
}

int main(int args, char** argv) {
    printf("Main thread: %ld\n", syscall(SYS_gettid));
    int n = 1;//std::min(NUM_THREADS, atoi(argv[1]));
    pthread_t t[n];
    // create the infinite loop thread for testing
    for(int i = 0; i < n; i++) {
        chs[i] = i + '0';
        pthread_create(&t[i], NULL, child_thread, &chs[i]);
    }

    // 等待子线程结束
    for(int i = 0; i < n; i++) {
        pthread_join(t[i], NULL);
    }

    return 0;
}
