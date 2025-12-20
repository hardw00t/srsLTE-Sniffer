/**
 * test_framework.h - Simple unit testing framework
 *
 * Lightweight testing framework inspired by Unity and MinUnit.
 * Provides assertions, test registration, and result reporting.
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

/*============================================================================
 * ANSI Colors
 *============================================================================*/

#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_RESET   "\x1b[0m"
#define ANSI_BOLD    "\x1b[1m"

/*============================================================================
 * Test State
 *============================================================================*/

typedef struct {
    int tests_run;
    int tests_passed;
    int tests_failed;
    int assertions_passed;
    int assertions_failed;
    const char *current_test;
    const char *current_file;
    int current_line;
    bool test_failed;
} test_state_t;

/* Global test state */
static test_state_t g_test_state = {0};

/*============================================================================
 * Test Result Macros
 *============================================================================*/

#define TEST_PASS() do { \
    g_test_state.assertions_passed++; \
} while(0)

#define TEST_FAIL(msg) do { \
    g_test_state.assertions_failed++; \
    g_test_state.test_failed = true; \
    fprintf(stderr, ANSI_RED "  FAIL" ANSI_RESET " %s:%d: %s\n", \
            __FILE__, __LINE__, msg); \
} while(0)

/*============================================================================
 * Assertions
 *============================================================================*/

#define ASSERT_TRUE(condition) do { \
    if (condition) { \
        TEST_PASS(); \
    } else { \
        TEST_FAIL("Expected true, got false"); \
    } \
} while(0)

#define ASSERT_FALSE(condition) do { \
    if (!(condition)) { \
        TEST_PASS(); \
    } else { \
        TEST_FAIL("Expected false, got true"); \
    } \
} while(0)

#define ASSERT_NULL(ptr) do { \
    if ((ptr) == NULL) { \
        TEST_PASS(); \
    } else { \
        TEST_FAIL("Expected NULL pointer"); \
    } \
} while(0)

#define ASSERT_NOT_NULL(ptr) do { \
    if ((ptr) != NULL) { \
        TEST_PASS(); \
    } else { \
        TEST_FAIL("Expected non-NULL pointer"); \
    } \
} while(0)

#define ASSERT_EQ(expected, actual) do { \
    if ((expected) == (actual)) { \
        TEST_PASS(); \
    } else { \
        char msg[256]; \
        snprintf(msg, sizeof(msg), "Expected %ld, got %ld", \
                 (long)(expected), (long)(actual)); \
        TEST_FAIL(msg); \
    } \
} while(0)

#define ASSERT_NE(not_expected, actual) do { \
    if ((not_expected) != (actual)) { \
        TEST_PASS(); \
    } else { \
        char msg[256]; \
        snprintf(msg, sizeof(msg), "Expected not %ld", (long)(not_expected)); \
        TEST_FAIL(msg); \
    } \
} while(0)

#define ASSERT_LT(actual, max) do { \
    if ((actual) < (max)) { \
        TEST_PASS(); \
    } else { \
        char msg[256]; \
        snprintf(msg, sizeof(msg), "Expected %ld < %ld", \
                 (long)(actual), (long)(max)); \
        TEST_FAIL(msg); \
    } \
} while(0)

#define ASSERT_LE(actual, max) do { \
    if ((actual) <= (max)) { \
        TEST_PASS(); \
    } else { \
        char msg[256]; \
        snprintf(msg, sizeof(msg), "Expected %ld <= %ld", \
                 (long)(actual), (long)(max)); \
        TEST_FAIL(msg); \
    } \
} while(0)

#define ASSERT_GT(actual, min) do { \
    if ((actual) > (min)) { \
        TEST_PASS(); \
    } else { \
        char msg[256]; \
        snprintf(msg, sizeof(msg), "Expected %ld > %ld", \
                 (long)(actual), (long)(min)); \
        TEST_FAIL(msg); \
    } \
} while(0)

#define ASSERT_GE(actual, min) do { \
    if ((actual) >= (min)) { \
        TEST_PASS(); \
    } else { \
        char msg[256]; \
        snprintf(msg, sizeof(msg), "Expected %ld >= %ld", \
                 (long)(actual), (long)(min)); \
        TEST_FAIL(msg); \
    } \
} while(0)

#define ASSERT_STR_EQ(expected, actual) do { \
    if ((expected) && (actual) && strcmp((expected), (actual)) == 0) { \
        TEST_PASS(); \
    } else { \
        char msg[256]; \
        snprintf(msg, sizeof(msg), "Expected \"%s\", got \"%s\"", \
                 (expected) ? (expected) : "NULL", \
                 (actual) ? (actual) : "NULL"); \
        TEST_FAIL(msg); \
    } \
} while(0)

#define ASSERT_STR_NE(not_expected, actual) do { \
    if (!(not_expected) || !(actual) || strcmp((not_expected), (actual)) != 0) { \
        TEST_PASS(); \
    } else { \
        TEST_FAIL("Strings should not be equal"); \
    } \
} while(0)

#define ASSERT_MEM_EQ(expected, actual, len) do { \
    if (memcmp((expected), (actual), (len)) == 0) { \
        TEST_PASS(); \
    } else { \
        TEST_FAIL("Memory regions differ"); \
    } \
} while(0)

#define ASSERT_FLOAT_EQ(expected, actual, epsilon) do { \
    double diff = fabs((double)(expected) - (double)(actual)); \
    if (diff <= (epsilon)) { \
        TEST_PASS(); \
    } else { \
        char msg[256]; \
        snprintf(msg, sizeof(msg), "Expected %f, got %f (diff=%f)", \
                 (double)(expected), (double)(actual), diff); \
        TEST_FAIL(msg); \
    } \
} while(0)

/*============================================================================
 * Test Registration and Running
 *============================================================================*/

typedef void (*test_fn)(void);

typedef struct {
    const char *name;
    test_fn     fn;
} test_case_t;

#define TEST(name) static void test_##name(void)

#define TEST_CASE(name) { #name, test_##name }

#define RUN_TEST(name) do { \
    g_test_state.current_test = #name; \
    g_test_state.test_failed = false; \
    g_test_state.tests_run++; \
    printf("  Running: %s... ", #name); \
    fflush(stdout); \
    test_##name(); \
    if (g_test_state.test_failed) { \
        g_test_state.tests_failed++; \
        printf(ANSI_RED "FAILED" ANSI_RESET "\n"); \
    } else { \
        g_test_state.tests_passed++; \
        printf(ANSI_GREEN "OK" ANSI_RESET "\n"); \
    } \
} while(0)

#define RUN_TEST_SUITE(suite_name, tests) do { \
    printf("\n" ANSI_BOLD ANSI_CYAN "=== %s ===" ANSI_RESET "\n", suite_name); \
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) { \
        g_test_state.current_test = tests[i].name; \
        g_test_state.test_failed = false; \
        g_test_state.tests_run++; \
        printf("  Running: %s... ", tests[i].name); \
        fflush(stdout); \
        tests[i].fn(); \
        if (g_test_state.test_failed) { \
            g_test_state.tests_failed++; \
            printf(ANSI_RED "FAILED" ANSI_RESET "\n"); \
        } else { \
            g_test_state.tests_passed++; \
            printf(ANSI_GREEN "OK" ANSI_RESET "\n"); \
        } \
    } \
} while(0)

/*============================================================================
 * Test Lifecycle
 *============================================================================*/

static inline void test_init(void) {
    memset(&g_test_state, 0, sizeof(g_test_state));
    printf(ANSI_BOLD "\n========================================\n");
    printf("  srsLTE-Sniffer Unit Tests\n");
    printf("========================================\n" ANSI_RESET);
}

static inline int test_summary(void) {
    printf("\n" ANSI_BOLD "========================================\n");
    printf("  Test Summary\n");
    printf("========================================" ANSI_RESET "\n");
    printf("  Tests run:     %d\n", g_test_state.tests_run);
    printf("  Tests passed:  " ANSI_GREEN "%d" ANSI_RESET "\n", g_test_state.tests_passed);
    printf("  Tests failed:  " ANSI_RED "%d" ANSI_RESET "\n", g_test_state.tests_failed);
    printf("  Assertions:    %d passed, %d failed\n",
           g_test_state.assertions_passed, g_test_state.assertions_failed);
    printf("\n");

    if (g_test_state.tests_failed == 0) {
        printf(ANSI_GREEN ANSI_BOLD "  All tests passed!" ANSI_RESET "\n\n");
        return 0;
    } else {
        printf(ANSI_RED ANSI_BOLD "  Some tests failed!" ANSI_RESET "\n\n");
        return 1;
    }
}

/*============================================================================
 * Setup/Teardown Support
 *============================================================================*/

typedef void (*setup_fn)(void);
typedef void (*teardown_fn)(void);

static setup_fn g_setup = NULL;
static teardown_fn g_teardown = NULL;

#define SET_SETUP(fn) g_setup = fn
#define SET_TEARDOWN(fn) g_teardown = fn

#define RUN_TEST_WITH_FIXTURE(name) do { \
    if (g_setup) g_setup(); \
    RUN_TEST(name); \
    if (g_teardown) g_teardown(); \
} while(0)

#endif /* TEST_FRAMEWORK_H */
