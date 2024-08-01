#include "log.h"
#include <cstdlib>
#include <stdarg.h>
#include <stdio.h>

void logMessage(LogLevel level, const char *file, int line, const char *format, ...)
{
#ifdef LOG_LEVEL
  if (level < LOG_LEVEL)
  {
    return;
  }
#endif
  const char *levelStr[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
  const char *colorStr[] = {COLOR_DEBUG, COLOR_INFO, COLOR_WARNING, COLOR_ERROR};

   printf("%s[%s:%d] %s: %s", colorStr[level], file, line, levelStr[level], COLOR_RESET);

  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
  puts("");

  if (level == LOG_ERROR)
  {
    // exit(EXIT_FAILURE);
  }
}