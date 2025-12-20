/**
 * test_logger.c - Tests for logging system
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include "logger.h"
#include <string.h>
#include <unistd.h>

/*============================================================================
 * Tests
 *============================================================================*/

TEST(logger_init_shutdown) {
    logger_config_t config;
    logger_config_default(&config);

    ASSERT_EQ(0, logger_init(&config));
    logger_shutdown();

    /* Multiple shutdowns should be safe */
    logger_shutdown();
}

TEST(logger_default_config) {
    logger_config_t config;
    logger_config_default(&config);

    ASSERT_FALSE(config.log_to_file);
    ASSERT_TRUE(config.log_to_console);
    ASSERT_TRUE(config.include_timestamp);
    ASSERT_TRUE(config.include_level);
    ASSERT_EQ(LOG_LEVEL_INFO, config.min_level);
}

TEST(logger_level_names) {
    ASSERT_STR_EQ("DEBUG", logger_level_name(LOG_LEVEL_DEBUG));
    ASSERT_STR_EQ("INFO", logger_level_name(LOG_LEVEL_INFO));
    ASSERT_STR_EQ("WARN", logger_level_name(LOG_LEVEL_WARN));
    ASSERT_STR_EQ("ERROR", logger_level_name(LOG_LEVEL_ERROR));
    ASSERT_STR_EQ("FATAL", logger_level_name(LOG_LEVEL_FATAL));
    ASSERT_STR_EQ("OFF", logger_level_name(LOG_LEVEL_OFF));
}

TEST(logger_level_from_string) {
    ASSERT_EQ(LOG_LEVEL_DEBUG, logger_level_from_string("debug"));
    ASSERT_EQ(LOG_LEVEL_DEBUG, logger_level_from_string("DEBUG"));
    ASSERT_EQ(LOG_LEVEL_INFO, logger_level_from_string("info"));
    ASSERT_EQ(LOG_LEVEL_WARN, logger_level_from_string("warn"));
    ASSERT_EQ(LOG_LEVEL_WARN, logger_level_from_string("warning"));
    ASSERT_EQ(LOG_LEVEL_ERROR, logger_level_from_string("error"));
    ASSERT_EQ(LOG_LEVEL_FATAL, logger_level_from_string("fatal"));
    ASSERT_EQ(LOG_LEVEL_OFF, logger_level_from_string("off"));
    ASSERT_EQ(LOG_LEVEL_INFO, logger_level_from_string("unknown"));
    ASSERT_EQ(LOG_LEVEL_INFO, logger_level_from_string(NULL));
}

TEST(logger_set_get_level) {
    logger_config_t config;
    logger_config_default(&config);
    config.min_level = LOG_LEVEL_DEBUG;
    logger_init(&config);

    ASSERT_EQ(LOG_LEVEL_DEBUG, logger_get_level());

    logger_set_level(LOG_LEVEL_ERROR);
    ASSERT_EQ(LOG_LEVEL_ERROR, logger_get_level());

    logger_shutdown();
}

TEST(logger_context) {
    logger_init(NULL);

    logger_ctx_t *ctx = logger_create("TestModule");
    ASSERT_NOT_NULL(ctx);

    /* Log with context - should not crash */
    LOGC_INFO(ctx, "Test message from context");

    logger_destroy(ctx);
    logger_shutdown();
}

TEST(logger_file_output) {
    const char *test_file = "/tmp/test_logger.log";

    /* Remove existing file */
    unlink(test_file);

    logger_config_t config;
    logger_config_default(&config);
    config.log_to_file = true;
    config.log_to_console = false;
    strncpy(config.log_file, test_file, sizeof(config.log_file) - 1);

    ASSERT_EQ(0, logger_init(&config));

    LOG_INFO("Test log message");
    logger_flush();

    /* Check file exists */
    FILE *fp = fopen(test_file, "r");
    ASSERT_NOT_NULL(fp);

    char line[256];
    ASSERT_NOT_NULL(fgets(line, sizeof(line), fp));
    ASSERT_NOT_NULL(strstr(line, "Test log message"));

    fclose(fp);
    logger_shutdown();

    unlink(test_file);
}

TEST(logger_level_filtering) {
    const char *test_file = "/tmp/test_logger_filter.log";
    unlink(test_file);

    logger_config_t config;
    logger_config_default(&config);
    config.log_to_file = true;
    config.log_to_console = false;
    config.min_level = LOG_LEVEL_WARN;
    strncpy(config.log_file, test_file, sizeof(config.log_file) - 1);

    ASSERT_EQ(0, logger_init(&config));

    LOG_DEBUG("Debug message");  /* Should be filtered */
    LOG_INFO("Info message");    /* Should be filtered */
    LOG_WARN("Warning message"); /* Should appear */
    logger_flush();

    FILE *fp = fopen(test_file, "r");
    ASSERT_NOT_NULL(fp);

    char line[256];
    char *result = fgets(line, sizeof(line), fp);
    if (result) {
        /* Should only have warning, not debug or info */
        ASSERT_NOT_NULL(strstr(line, "Warning"));
        ASSERT_NULL(strstr(line, "Debug"));
        ASSERT_NULL(strstr(line, "Info"));
    }

    fclose(fp);
    logger_shutdown();
    unlink(test_file);
}

TEST(logger_null_context_safe) {
    logger_init(NULL);

    /* Should not crash with NULL context */
    logger_log_ctx(NULL, LOG_LEVEL_INFO, __FILE__, __LINE__, "Test");

    logger_shutdown();
}

TEST(logger_auto_init) {
    /* Logger should auto-init if used without explicit init */
    logger_shutdown();  /* Ensure clean state */

    LOG_INFO("Auto-init test");  /* Should auto-init */

    logger_shutdown();
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_logger_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== Logger Tests ===" ANSI_RESET "\n");

    RUN_TEST(logger_init_shutdown);
    RUN_TEST(logger_default_config);
    RUN_TEST(logger_level_names);
    RUN_TEST(logger_level_from_string);
    RUN_TEST(logger_set_get_level);
    RUN_TEST(logger_context);
    RUN_TEST(logger_file_output);
    RUN_TEST(logger_level_filtering);
    RUN_TEST(logger_null_context_safe);
    RUN_TEST(logger_auto_init);
}
