/**
 * logger.c - Production-ready logging implementation
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

/*============================================================================
 * ANSI Color Codes
 *============================================================================*/

#define ANSI_RESET   "\x1b[0m"
#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_BLUE    "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_WHITE   "\x1b[37m"
#define ANSI_BOLD    "\x1b[1m"

/*============================================================================
 * Level Names and Colors
 *============================================================================*/

static const char *level_names[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "OFF"
};

static const char *level_colors[] = {
    ANSI_CYAN,    /* DEBUG */
    ANSI_GREEN,   /* INFO */
    ANSI_YELLOW,  /* WARN */
    ANSI_RED,     /* ERROR */
    ANSI_BOLD ANSI_RED  /* FATAL */
};

/*============================================================================
 * Global Logger State
 *============================================================================*/

struct logger_ctx {
    char name[64];
};

typedef struct {
    logger_config_t config;
    FILE           *log_fp;
    pthread_mutex_t mutex;
    bool            initialized;
    uint64_t        current_size;
    time_t          last_rotation;
    int             rotation_count;
} global_logger_t;

static global_logger_t g_logger = {0};

/*============================================================================
 * Default Configuration
 *============================================================================*/

void logger_config_default(logger_config_t *config) {
    if (!config) return;

    memset(config, 0, sizeof(logger_config_t));

    config->log_to_file = false;
    config->log_to_console = true;
    config->log_to_syslog = false;

    config->min_level = LOG_LEVEL_INFO;
    config->console_level = LOG_LEVEL_INFO;

    config->include_timestamp = true;
    config->include_level = true;
    config->include_source = false;
    config->color_output = true;

    config->rotation = ROTATE_NONE;
    config->max_file_size = 10 * 1024 * 1024;  /* 10 MB */
    config->max_rotated_files = LOG_MAX_ROTATED;
    config->compress_rotated = false;

    config->async_logging = false;
    config->buffer_size = 8192;
}

/*============================================================================
 * Initialization / Shutdown
 *============================================================================*/

int logger_init(const logger_config_t *config) {
    if (g_logger.initialized) {
        return 0;  /* Already initialized */
    }

    /* Apply config or defaults */
    if (config) {
        memcpy(&g_logger.config, config, sizeof(logger_config_t));
    } else {
        logger_config_default(&g_logger.config);
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&g_logger.mutex, NULL) != 0) {
        fprintf(stderr, "Logger: Failed to initialize mutex\n");
        return -1;
    }

    /* Open log file if configured */
    if (g_logger.config.log_to_file && g_logger.config.log_file[0] != '\0') {
        g_logger.log_fp = fopen(g_logger.config.log_file, "a");
        if (!g_logger.log_fp) {
            fprintf(stderr, "Logger: Failed to open log file '%s': %s\n",
                    g_logger.config.log_file, strerror(errno));
            pthread_mutex_destroy(&g_logger.mutex);
            return -1;
        }

        /* Get current file size */
        fseek(g_logger.log_fp, 0, SEEK_END);
        g_logger.current_size = ftell(g_logger.log_fp);
    }

    g_logger.last_rotation = time(NULL);
    g_logger.initialized = true;

    return 0;
}

void logger_shutdown(void) {
    if (!g_logger.initialized) {
        return;
    }

    pthread_mutex_lock(&g_logger.mutex);

    if (g_logger.log_fp) {
        fflush(g_logger.log_fp);
        fclose(g_logger.log_fp);
        g_logger.log_fp = NULL;
    }

    pthread_mutex_unlock(&g_logger.mutex);
    pthread_mutex_destroy(&g_logger.mutex);

    g_logger.initialized = false;
}

/*============================================================================
 * Logger Context
 *============================================================================*/

logger_ctx_t *logger_create(const char *name) {
    logger_ctx_t *ctx = calloc(1, sizeof(logger_ctx_t));
    if (!ctx) return NULL;

    if (name) {
        strncpy(ctx->name, name, sizeof(ctx->name) - 1);
    }

    return ctx;
}

void logger_destroy(logger_ctx_t *ctx) {
    free(ctx);
}

/*============================================================================
 * Rotation
 *============================================================================*/

static int rotate_log_files(void) {
    if (!g_logger.log_fp || g_logger.config.log_file[0] == '\0') {
        return 0;
    }

    char old_name[LOG_MAX_FILENAME + 16];
    char new_name[LOG_MAX_FILENAME + 16];

    /* Close current file */
    fclose(g_logger.log_fp);
    g_logger.log_fp = NULL;

    /* Delete oldest file if at max */
    snprintf(old_name, sizeof(old_name), "%s.%d",
             g_logger.config.log_file, g_logger.config.max_rotated_files);
    unlink(old_name);

    /* Rotate existing files */
    for (int i = g_logger.config.max_rotated_files - 1; i >= 1; i--) {
        snprintf(old_name, sizeof(old_name), "%s.%d", g_logger.config.log_file, i);
        snprintf(new_name, sizeof(new_name), "%s.%d", g_logger.config.log_file, i + 1);
        rename(old_name, new_name);
    }

    /* Rotate current file to .1 */
    snprintf(new_name, sizeof(new_name), "%s.1", g_logger.config.log_file);
    rename(g_logger.config.log_file, new_name);

    /* Open new log file */
    g_logger.log_fp = fopen(g_logger.config.log_file, "w");
    if (!g_logger.log_fp) {
        fprintf(stderr, "Logger: Failed to create new log file\n");
        return -1;
    }

    g_logger.current_size = 0;
    g_logger.last_rotation = time(NULL);
    g_logger.rotation_count++;

    return 0;
}

static bool should_rotate(void) {
    if (g_logger.config.rotation == ROTATE_NONE) {
        return false;
    }

    time_t now = time(NULL);
    struct tm now_tm, last_tm;

    switch (g_logger.config.rotation) {
        case ROTATE_SIZE:
            return g_logger.current_size >= g_logger.config.max_file_size;

        case ROTATE_DAILY:
            localtime_r(&now, &now_tm);
            localtime_r(&g_logger.last_rotation, &last_tm);
            return now_tm.tm_yday != last_tm.tm_yday ||
                   now_tm.tm_year != last_tm.tm_year;

        case ROTATE_HOURLY:
            localtime_r(&now, &now_tm);
            localtime_r(&g_logger.last_rotation, &last_tm);
            return now_tm.tm_hour != last_tm.tm_hour ||
                   now_tm.tm_yday != last_tm.tm_yday;

        default:
            return false;
    }
}

int logger_rotate(void) {
    if (!g_logger.initialized) {
        return -1;
    }

    pthread_mutex_lock(&g_logger.mutex);
    int ret = rotate_log_files();
    pthread_mutex_unlock(&g_logger.mutex);

    return ret;
}

/*============================================================================
 * Core Logging
 *============================================================================*/

static void format_timestamp(char *buf, size_t len) {
    struct timespec ts;
    struct tm tm_info;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);

    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
             tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
             ts.tv_nsec / 1000000);
}

void logger_vlog_ctx(logger_ctx_t *ctx, log_level_t level,
                     const char *file, int line,
                     const char *fmt, va_list args) {
    if (!g_logger.initialized) {
        /* Auto-initialize with defaults if needed */
        if (logger_init(NULL) != 0) {
            return;
        }
    }

    if (level < g_logger.config.min_level) {
        return;
    }

    pthread_mutex_lock(&g_logger.mutex);

    char timestamp[32];
    char message[LOG_MAX_MESSAGE];
    int msg_len;

    /* Format timestamp */
    if (g_logger.config.include_timestamp) {
        format_timestamp(timestamp, sizeof(timestamp));
    }

    /* Format message */
    msg_len = vsnprintf(message, sizeof(message), fmt, args);
    if (msg_len < 0) msg_len = 0;

    /* Write to console */
    if (g_logger.config.log_to_console && level >= g_logger.config.console_level) {
        FILE *out = (level >= LOG_LEVEL_ERROR) ? stderr : stdout;

        if (g_logger.config.color_output && level < LOG_LEVEL_OFF) {
            fprintf(out, "%s", level_colors[level]);
        }

        if (g_logger.config.include_timestamp) {
            fprintf(out, "[%s] ", timestamp);
        }

        if (g_logger.config.include_level) {
            fprintf(out, "[%-5s] ", level_names[level]);
        }

        if (ctx && ctx->name[0]) {
            fprintf(out, "[%s] ", ctx->name);
        }

        if (g_logger.config.include_source && file) {
            const char *basename = strrchr(file, '/');
            basename = basename ? basename + 1 : file;
            fprintf(out, "(%s:%d) ", basename, line);
        }

        fprintf(out, "%s", message);

        if (g_logger.config.color_output && level < LOG_LEVEL_OFF) {
            fprintf(out, "%s", ANSI_RESET);
        }

        fprintf(out, "\n");
        fflush(out);
    }

    /* Write to file */
    if (g_logger.config.log_to_file && g_logger.log_fp) {
        int written = 0;

        if (g_logger.config.include_timestamp) {
            written += fprintf(g_logger.log_fp, "[%s] ", timestamp);
        }

        if (g_logger.config.include_level) {
            written += fprintf(g_logger.log_fp, "[%-5s] ", level_names[level]);
        }

        if (ctx && ctx->name[0]) {
            written += fprintf(g_logger.log_fp, "[%s] ", ctx->name);
        }

        if (g_logger.config.include_source && file) {
            const char *basename = strrchr(file, '/');
            basename = basename ? basename + 1 : file;
            written += fprintf(g_logger.log_fp, "(%s:%d) ", basename, line);
        }

        written += fprintf(g_logger.log_fp, "%s\n", message);
        fflush(g_logger.log_fp);

        g_logger.current_size += written;

        /* Check if rotation needed */
        if (should_rotate()) {
            rotate_log_files();
        }
    }

    pthread_mutex_unlock(&g_logger.mutex);
}

void logger_vlog(log_level_t level, const char *file, int line,
                 const char *fmt, va_list args) {
    logger_vlog_ctx(NULL, level, file, line, fmt, args);
}

void logger_log(log_level_t level, const char *file, int line,
                const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    logger_vlog(level, file, line, fmt, args);
    va_end(args);
}

void logger_log_ctx(logger_ctx_t *ctx, log_level_t level,
                    const char *file, int line,
                    const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    logger_vlog_ctx(ctx, level, file, line, fmt, args);
    va_end(args);
}

/*============================================================================
 * Utility Functions
 *============================================================================*/

void logger_set_level(log_level_t level) {
    if (g_logger.initialized) {
        pthread_mutex_lock(&g_logger.mutex);
        g_logger.config.min_level = level;
        pthread_mutex_unlock(&g_logger.mutex);
    }
}

log_level_t logger_get_level(void) {
    return g_logger.config.min_level;
}

void logger_flush(void) {
    if (g_logger.initialized && g_logger.log_fp) {
        pthread_mutex_lock(&g_logger.mutex);
        fflush(g_logger.log_fp);
        pthread_mutex_unlock(&g_logger.mutex);
    }
}

const char *logger_level_name(log_level_t level) {
    if (level >= 0 && level <= LOG_LEVEL_OFF) {
        return level_names[level];
    }
    return "UNKNOWN";
}

log_level_t logger_level_from_string(const char *str) {
    if (!str) return LOG_LEVEL_INFO;

    if (strcasecmp(str, "debug") == 0) return LOG_LEVEL_DEBUG;
    if (strcasecmp(str, "info") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "warning") == 0) return LOG_LEVEL_WARN;
    if (strcasecmp(str, "error") == 0) return LOG_LEVEL_ERROR;
    if (strcasecmp(str, "fatal") == 0) return LOG_LEVEL_FATAL;
    if (strcasecmp(str, "off") == 0 || strcasecmp(str, "none") == 0) return LOG_LEVEL_OFF;

    return LOG_LEVEL_INFO;
}

void logger_hex_dump(log_level_t level, const char *prefix,
                     const void *data, size_t len) {
    if (level < g_logger.config.min_level) {
        return;
    }

    const uint8_t *bytes = (const uint8_t *)data;
    char line[80];
    char ascii[17];

    for (size_t i = 0; i < len; i += 16) {
        int pos = snprintf(line, sizeof(line), "%s%04zx: ", prefix ? prefix : "", i);

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", bytes[i + j]);
                ascii[j] = (bytes[i + j] >= 32 && bytes[i + j] < 127) ? bytes[i + j] : '.';
            } else {
                pos += snprintf(line + pos, sizeof(line) - pos, "   ");
                ascii[j] = ' ';
            }
        }
        ascii[16] = '\0';

        snprintf(line + pos, sizeof(line) - pos, " |%s|", ascii);
        logger_log(level, NULL, 0, "%s", line);
    }
}
