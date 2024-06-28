#ifndef MY_LOG
#define MY_LOG
typedef enum
{
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LogLevel;

#define COLOR_RESET "\x1b[0m"
#define COLOR_DEBUG "\x1b[34m"
#define COLOR_INFO "\x1b[32m"
#define COLOR_WARNING "\x1b[33m"
#define COLOR_ERROR "\x1b[31m"

void logMessage(LogLevel level, const char *file, int line, const char *format, ...);

#define LOG(level, ...) logMessage(level, __FILE__, __LINE__, __VA_ARGS__)

#define DEBUG(...) LOG(LOG_DEBUG, __VA_ARGS__)
#define INFO(...) LOG(LOG_INFO, __VA_ARGS__)
#define WARNING(...) LOG(LOG_WARNING, __VA_ARGS__)
#define ERROR(...) LOG(LOG_ERROR, __VA_ARGS__)

#endif