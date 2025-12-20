/**
 * test_sib_parser.c - Tests for SIB parser
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include "sib_parser.h"

/*============================================================================
 * Bit Reader Tests
 *============================================================================*/

TEST(bit_reader_init) {
    uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    ASSERT_EQ(0, br.bit_pos);
    ASSERT_EQ(sizeof(data), br.len);
    ASSERT_EQ(32, bit_reader_remaining(&br));
}

TEST(bit_reader_read_bits) {
    uint8_t data[] = {0xAB, 0xCD};  /* 1010 1011 1100 1101 */
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    /* Read 4 bits: 1010 = 10 */
    ASSERT_EQ(10, bit_reader_read(&br, 4));

    /* Read 4 bits: 1011 = 11 */
    ASSERT_EQ(11, bit_reader_read(&br, 4));

    /* Read 8 bits: 1100 1101 = 205 */
    ASSERT_EQ(205, bit_reader_read(&br, 8));

    /* Should have 0 bits remaining */
    ASSERT_EQ(0, bit_reader_remaining(&br));
}

TEST(bit_reader_read_single_bit) {
    uint8_t data[] = {0x80};  /* 1000 0000 */
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    ASSERT_EQ(1, bit_reader_read(&br, 1));
    ASSERT_EQ(0, bit_reader_read(&br, 1));
    ASSERT_EQ(0, bit_reader_read(&br, 1));
}

TEST(bit_reader_skip) {
    uint8_t data[] = {0xFF, 0x00, 0xAA};
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    bit_reader_skip(&br, 8);  /* Skip first byte */
    ASSERT_EQ(16, bit_reader_remaining(&br));

    bit_reader_skip(&br, 4);  /* Skip 4 bits of 0x00 */
    ASSERT_EQ(12, bit_reader_remaining(&br));
}

TEST(bit_reader_has_bits) {
    uint8_t data[] = {0xFF};
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    ASSERT_TRUE(bit_reader_has_bits(&br, 8));
    ASSERT_TRUE(bit_reader_has_bits(&br, 1));
    ASSERT_FALSE(bit_reader_has_bits(&br, 9));

    bit_reader_skip(&br, 4);
    ASSERT_TRUE(bit_reader_has_bits(&br, 4));
    ASSERT_FALSE(bit_reader_has_bits(&br, 5));
}

/*============================================================================
 * SI Window Calculation Tests
 *============================================================================*/

TEST(si_window_active_check) {
    si_window_t window = {
        .start_sfn = 100,
        .start_subframe = 0,
        .end_sfn = 100,
        .end_subframe = 9
    };

    /* Inside window */
    ASSERT_TRUE(si_window_is_active(&window, 100, 0));
    ASSERT_TRUE(si_window_is_active(&window, 100, 5));
    ASSERT_TRUE(si_window_is_active(&window, 100, 9));

    /* Outside window */
    ASSERT_FALSE(si_window_is_active(&window, 99, 9));
    ASSERT_FALSE(si_window_is_active(&window, 101, 0));
}

TEST(si_window_wraparound) {
    si_window_t window = {
        .start_sfn = 1020,
        .start_subframe = 5,
        .end_sfn = 2,   /* Wrapped around */
        .end_subframe = 5
    };

    /* SFN wraps at 1024 */
    ASSERT_TRUE(si_window_is_active(&window, 1020, 5));
    ASSERT_TRUE(si_window_is_active(&window, 1023, 9));
    ASSERT_TRUE(si_window_is_active(&window, 0, 0));
    ASSERT_TRUE(si_window_is_active(&window, 2, 5));

    ASSERT_FALSE(si_window_is_active(&window, 2, 6));
    ASSERT_FALSE(si_window_is_active(&window, 3, 0));
}

/*============================================================================
 * SIB1 Info Tests
 *============================================================================*/

TEST(sib1_info_init) {
    sib1_info_t info;
    memset(&info, 0, sizeof(info));

    ASSERT_FALSE(info.valid);
    ASSERT_EQ(0, info.num_plmn_ids);
    ASSERT_FALSE(info.sib2_found);
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_sib_parser_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== SIB Parser Tests ===" ANSI_RESET "\n");

    RUN_TEST(bit_reader_init);
    RUN_TEST(bit_reader_read_bits);
    RUN_TEST(bit_reader_read_single_bit);
    RUN_TEST(bit_reader_skip);
    RUN_TEST(bit_reader_has_bits);
    RUN_TEST(si_window_active_check);
    RUN_TEST(si_window_wraparound);
    RUN_TEST(sib1_info_init);
}
