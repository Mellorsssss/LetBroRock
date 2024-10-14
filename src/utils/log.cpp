#include "log.h"

#include <chrono>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iomanip>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

const int BUFFER_SIZE = 1024;

void initLogFile() {
	logFd = open("profiler.log", O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (logFd == -1) {
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
	// add timestamp for debugging
	auto now = std::chrono::system_clock::now();
	std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
	auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
	std::tm now_tm = *std::localtime(&now_time_t);

	char buffer[BUFFER_SIZE];
	int offset = offset =
	    snprintf(buffer, BUFFER_SIZE, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ", now_tm.tm_year + 1900, now_tm.tm_mon + 1,
	             now_tm.tm_mday, now_tm.tm_hour, now_tm.tm_min, now_tm.tm_sec, (int)milliseconds.count());

	offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "[%s:%d] %s:", file, line, levelStr[level]);

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