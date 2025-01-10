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
bool ENABLE_LOG = true;
bool ENABLE_TIMESTAMP = true;
LogLevel LOG_LEVEL = LOG_DEBUG;

void initLogFile() {
	logFd = open("profiler.log", O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (logFd == -1) {
		exit(EXIT_FAILURE);
	}
}

void logMessage(LogLevel level, const char *file, int line, const char *format, ...) {
	if (!ENABLE_LOG) {
		return;
	}

	if (level < LOG_LEVEL) {
		return;
	}

	const char *levelStr[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
	const char *colorStr[] = {COLOR_DEBUG, COLOR_INFO, COLOR_WARNING, COLOR_ERROR};

	if (logFd == -1) {
		initLogFile();
	}

	if (!ENABLE_TIMESTAMP) {
		char buffer[BUFFER_SIZE];
		int offset = snprintf(buffer, BUFFER_SIZE, "[%s:%d] %s:", file, line, levelStr[level]);

		va_list args;
		va_start(args, format);
		vsnprintf(buffer + offset, BUFFER_SIZE - offset, format, args);
		va_end(args);

		strcat(buffer, "\n");
		write(logFd, buffer, strlen(buffer));
		void(fsync(logFd));
		// if (level == LOG_ERROR) {
		// exit(EXIT_FAILURE);
		// }
		return;
	}
	// clock_gettime is async signal safe
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm now_tm;
	localtime_r(&ts.tv_sec, &now_tm);

	char buffer[BUFFER_SIZE];
	int offset =
	    snprintf(buffer, BUFFER_SIZE, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] ", now_tm.tm_year + 1900,
	             now_tm.tm_mon + 1, now_tm.tm_mday, now_tm.tm_hour, now_tm.tm_min, now_tm.tm_sec, ts.tv_nsec / 1000000);

	offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "[%s:%d] %s:", file, line, levelStr[level]);

	va_list args;
	va_start(args, format);
	vsnprintf(buffer + offset, BUFFER_SIZE - offset, format, args);
	va_end(args);

	strcat(buffer, "\n");
	write(logFd, buffer, strlen(buffer));
	void(fsync(logFd));
	// if (level == LOG_ERROR) {
	// exit(EXIT_FAILURE);
	// }
}