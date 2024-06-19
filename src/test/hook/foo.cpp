#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "dbg.h"

// Original signal handler
void original_signal_handler(int signum) {
    printf("Original handler: Caught signal %d\n", signum);
}

int main() {
    pid_t pid = fork();

    if (pid < 0)
    {
        // Fork failed
        perror("Profiler failed to fork >:|");
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
        dbg("in child process");
        while(1) {
            pause();
        }
    }
    else {
        dbg("in parent process");
        while(1) {
            pause();
        }
    }
}
