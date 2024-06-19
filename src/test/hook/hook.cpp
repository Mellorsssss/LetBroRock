#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/wait.h>

// Original function pointers


// Constructor to set up hooks
__attribute__((constructor)) void setup_hooks() {
    
    pid_t target_pid;

    // Fork a new process
    target_pid = fork();

    if (target_pid < 0) {
        // Fork failed
        perror("Profiler failed to fork >:|");
        exit(EXIT_FAILURE);
    } else if (target_pid == 0) {
        // Child process
        // The child process will continue execution as normal, e.g: gaussDB will continue its work
        atexit([](){
            printf("Just for testing :D Hooked exit function\n");
        });

        printf("Child process (PID: %d) continuing with current command.\n", getpid());
    } else {
        // Profiler process
        printf("Profiler process (PID: %d) executing other logic.\n", getpid());

        int status;
        waitpid(target_pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("Child process exited with status %d.\n", WEXITSTATUS(status));
        } else {
            printf("Child process did not exit normally.\n");
        }

        // Optionally, exit the parent process if it's not needed
        exit(EXIT_SUCCESS);
    }
}
