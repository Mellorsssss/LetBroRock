/* This file is used to test the size of debug register. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <cstdint>

// syscall wrapper for perf_event_open
long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    struct perf_event_attr pe;
    int fds[6]; // Try to create 6 breakpoints, more than available

    for (int i = 0; i < 6; i++) {
        memset(&pe, 0, sizeof(struct perf_event_attr));
        pe.type = PERF_TYPE_BREAKPOINT;
        pe.size = sizeof(struct perf_event_attr);
        pe.config = 0;
        pe.bp_type = HW_BREAKPOINT_X;
        pe.bp_addr = (uintptr_t)&main + i * 16; // Different addresses
        pe.bp_len = sizeof(long);
        pe.sample_period = 1;
        pe.disabled = 0;

        fds[i] = perf_event_open(&pe, 0, -1, -1, 0);
        if (fds[i] == -1) {
            perror("perf_event_open");
            printf("Failed to create breakpoint %d\n", i);
        } else {
            printf("Created breakpoint %d at address %p\n", i, (void *)(pe.bp_addr));
        }
        if (i >= 4) {
          close(fds[i]);
          fds[i] = -1;
        }
    }

    // Close the file descriptors for cleanup
    for (int i = 0; i < 6; i++) {
        if (fds[i] != -1) {
            close(fds[i]);
        }
    }

    return 0;
}
