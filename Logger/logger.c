//
// Created by cryptic on 12/22/24.
//

/**
 * @file logger.c
 * @author Cryptiiiic
 * @brief This file is for all logger related code.
 * @version 1.0.1
 * @date 2024-12-22
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <stdarg.h>
#include <x8A4/Logger/logger.h>
#include <x8A4/x8A4.h>
#include <x8A4_state.h>

/* Functions */
/**
 * @brief           Print format string to a specified file stream
 * @param[in]       stream
 * @param[in]       format
 * @param[in]       __VA_ARGS__
 */
void x8A4_log_print(FILE *stream, const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stream, format, args);
  va_end(args);
}

/**
 * @brief           Print format string with a va_list to a specified file stream
 * @param[in]       stream
 * @param[in]       format
 * @param[in]       args
 */
void x8A4_log_print_va(FILE *stream, const char *format, va_list args) {
  vfprintf(stream, format, args);
}

/**
 * @brief           Print format string with a va_list to a specified file stream, include function name
 * @param[in]       stream
 * @param[in]       func
 * @param[in]       format
 * @param[in]       args
 */
void x8A4_log_function(FILE *stream, const char *func, const char *format, va_list args) {
  char format_out[PATH_MAX];
  char new_format[PATH_MAX];
  vsnprintf(format_out, PATH_MAX, format, args);
  strncpy(new_format, "[+]: %s: %s", 13);
  if(stream == stderr) {
    new_format[1] = '-';
  }
  x8A4_log_print(stream, new_format, func, format_out);
}

/**
 * @brief           Call the correct logger print based on log level
 * @param[in]       level
 * @param[in]       func
 * @param[in]       format
 * @param[in]       __VA_ARGS__
 */
void x8A4_logger(enum LOG_LEVEL level, const char *func, const char *format, ...) {
  FILE *stream = stdout;
  if(level == LOG_ERROR || level == LOG_DEBUG_ERROR) {
    stream = stderr;
  }
  va_list args;
  va_start(args, format);
  if(verbose_cached) {
    if(level == LOG_DEBUG || level == LOG_DEBUG_ERROR || level == LOG_ERROR) {
      x8A4_log_function(stream, func, format, args);
    }
  } else {
    if(level == LOG_ERROR) {
      x8A4_log_function(stream, func, format, args);
    }
  }
  if(level == LOG_INFO) {
    x8A4_log_print_va(stream, format, args);
  }
  va_end(args);
}
