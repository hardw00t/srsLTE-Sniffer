/**
 * test_main.c - Main test runner
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"

/* External test suite declarations */
extern void run_sib_parser_tests(void);
extern void run_data_handler_tests(void);
extern void run_bit_reader_tests(void);
extern void run_identity_tracker_tests(void);
extern void run_memory_pool_tests(void);
extern void run_logger_tests(void);
extern void run_config_parser_tests(void);
extern void run_convert_csv_tests(void);
extern void run_mib_parser_tests(void);
extern void run_paging_parser_tests(void);

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    test_init();

    /* Run all test suites */
    run_sib_parser_tests();
    run_data_handler_tests();
    run_bit_reader_tests();
    run_identity_tracker_tests();
    run_memory_pool_tests();
    run_logger_tests();
    run_config_parser_tests();
    run_convert_csv_tests();
    run_mib_parser_tests();
    run_paging_parser_tests();

    return test_summary();
}
