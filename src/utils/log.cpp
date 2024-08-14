#include "log.h"
#include <cstdlib>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

const int BUFFER_SIZE = 512;

void initLogFile() {
    logFd = open("profiler.log", O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (logFd == -1) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
}

void logMessage(LogLevel level, const char *file, int line, const char *format, ...) {
#ifdef LOG_LEVEL
    if (level < LOG_LEVEL) {
        return;
    }
#endif
    const char *levelStr[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
    const char *colorStr[] = {COLOR_DEBUG, COLOR_INFO, COLOR_WARNING, COLOR_ERROR};

    if (logFd == -1) {
        initLogFile();
    }

    char buffer[BUFFER_SIZE];
    int offset = snprintf(buffer, BUFFER_SIZE, "[%s:%d] %s:", file, line, levelStr[level]);

    va_list args;
    va_start(args, format);
    vsnprintf(buffer + offset, BUFFER_SIZE - offset, format, args);
    va_end(args);

    strcat(buffer, "\n");
    write(logFd, buffer, strlen(buffer));
    void(fsync(logFd));
    if (level == LOG_ERROR) {
        // exit(EXIT_FAILURE);
    }
}