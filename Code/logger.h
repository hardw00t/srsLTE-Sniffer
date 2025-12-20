/**
 * logger.h - Production-ready logging with rotation and compression
 *
 * Features:
 * - Log levels: DEBUG, INFO, WARN, ERROR, FATAL
 * - File rotation by size or time
 * - Optional gzip compression of rotated logs
 * - Thread-safe logging
 * - Syslog integration option
 * - Colored console output
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Log Levels
 *============================================================================*/

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_FATAL = 4,
    LOG_LEVEL_OFF   = 5
} log_level_t;

/*============================================================================
 * Rotation Policy
 *============================================================================*/

typedef enum {
    ROTATE_NONE = 0,      /* No rotation */
    ROTATE_SIZE,          /* Rotate by file size */
    ROTATE_DAILY,         /* Rotate daily */
    ROTATE_HOURLY         /* Rotate hourly */
} rotation_policy_t;

/*============================================================================
 * Logger Configuration
 *============================================================================*/

#define LOG_MAX_FILENAME    256
#define LOG_MAX_MESSAGE     4096
#define LOG_MAX_ROTATED     10   /* Maximum rotated files to keep */

typedef struct {
    /* Output settings */
    char            log_file[LOG_MAX_FILENAME];
    bool            log_to_file;
    bool            log_to_console;
    bool            log_to_syslog;

    /* Level filtering */
    log_level_t     min_level;
    log_level_t     console_level;

    /* Formatting */
    bool            include_timestamp;
    bool            include_level;
    bool            include_source;    /* File:line info */
    bool            color_output;      /* ANSI colors on console */

    /* Rotation */
    rotation_policy_t rotation;
    uint64_t        max_file_size;     /* Bytes, for ROTATE_SIZE */
    uint32_t        max_rotated_files;
    bool            compress_rotated;   /* gzip old files */

    /* Performance */
    bool            async_logging;      /* Background thread for I/O */
    uint32_t        buffer_size;        /* Async buffer size */
} logger_config_t;

/*============================================================================
 * Logger Context
 *============================================================================*/

typedef struct logger_ctx logger_ctx_t;

/*============================================================================
 * Default Configuration
 *============================================================================*/

/**
 * Get default logger configuration
 */
void logger_config_default(logger_config_t *config);

/*============================================================================
 * Logger Lifecycle
 *============================================================================*/

/**
 * Initialize global logger with configuration
 * @param config    Logger configuration (NULL for defaults)
 * @return          0 on success, -1 on error
 */
int logger_init(const logger_config_t *config);

/**
 * Shutdown global logger, flush buffers
 */
void logger_shutdown(void);

/**
 * Create a named logger context for module-specific logging
 * @param name      Module name for log prefix
 * @return          Logger context or NULL on error
 */
logger_ctx_t *logger_create(const char *name);

/**
 * Destroy logger context
 */
void logger_destroy(logger_ctx_t *ctx);

/*============================================================================
 * Logging Functions
 *============================================================================*/

/**
 * Log a message at specified level
 * @param level     Log level
 * @param file      Source file (use __FILE__)
 * @param line      Source line (use __LINE__)
 * @param fmt       Format string
 * @param ...       Format arguments
 */
void logger_log(log_level_t level, const char *file, int line,
                const char *fmt, ...) __attribute__((format(printf, 4, 5)));

/**
 * Log with context
 */
void logger_log_ctx(logger_ctx_t *ctx, log_level_t level,
                    const char *file, int line,
                    const char *fmt, ...) __attribute__((format(printf, 5, 6)));

/**
 * Variadic versions
 */
void logger_vlog(log_level_t level, const char *file, int line,
                 const char *fmt, va_list args);
void logger_vlog_ctx(logger_ctx_t *ctx, log_level_t level,
                     const char *file, int line,
                     const char *fmt, va_list args);

/*============================================================================
 * Convenience Macros
 *============================================================================*/

#define LOG_DEBUG(fmt, ...) \
    logger_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    logger_log(LOG_LEVEL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    logger_log(LOG_LEVEL_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
    logger_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_FATAL(fmt, ...) \
    logger_log(LOG_LEVEL_FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/* Context-specific logging */
#define LOGC_DEBUG(ctx, fmt, ...) \
    logger_log_ctx(ctx, LOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOGC_INFO(ctx, fmt, ...) \
    logger_log_ctx(ctx, LOG_LEVEL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOGC_WARN(ctx, fmt, ...) \
    logger_log_ctx(ctx, LOG_LEVEL_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOGC_ERROR(ctx, fmt, ...) \
    logger_log_ctx(ctx, LOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/*============================================================================
 * Log Management
 *============================================================================*/

/**
 * Set runtime log level
 */
void logger_set_level(log_level_t level);

/**
 * Get current log level
 */
log_level_t logger_get_level(void);

/**
 * Force log rotation
 */
int logger_rotate(void);

/**
 * Flush log buffers
 */
void logger_flush(void);

/**
 * Get log level name
 */
const char *logger_level_name(log_level_t level);

/**
 * Parse log level from string
 */
log_level_t logger_level_from_string(const char *str);

/*============================================================================
 * Hex Dump Utility
 *============================================================================*/

/**
 * Log a hex dump of data
 */
void logger_hex_dump(log_level_t level, const char *prefix,
                     const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */
