/**
 * test_bit_reader.c - Comprehensive bit reader tests
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include "sib_parser.h"

/*============================================================================
 * Tests
 *============================================================================*/

TEST(bit_reader_cross_byte_read) {
    /* Test reading values that cross byte boundaries */
    uint8_t data[] = {0xAB, 0xCD, 0xEF};  /* 1010 1011 | 1100 1101 | 1110 1111 */
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    /* Read 12 bits: 1010 1011 1100 = 0xABC = 2748 */
    uint32_t val = bit_reader_read(&br, 12);
    ASSERT_EQ(0xABC, val);

    /* Read remaining 12 bits: 1101 1110 1111 = 0xDEF = 3567 */
    val = bit_reader_read(&br, 12);
    ASSERT_EQ(0xDEF, val);
}

TEST(bit_reader_single_byte) {
    uint8_t data[] = {0xFF};
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    ASSERT_EQ(255, bit_reader_read(&br, 8));
    ASSERT_EQ(0, bit_reader_remaining(&br));
}

TEST(bit_reader_read_32_bits) {
    uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    uint32_t val = bit_reader_read(&br, 32);
    ASSERT_EQ(0x12345678, val);
}

TEST(bit_reader_mixed_reads) {
    uint8_t data[] = {0xF0, 0x0F};  /* 1111 0000 | 0000 1111 */
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    ASSERT_EQ(15, bit_reader_read(&br, 4));   /* 1111 = 15 */
    ASSERT_EQ(0, bit_reader_read(&br, 4));    /* 0000 = 0 */
    ASSERT_EQ(0, bit_reader_read(&br, 4));    /* 0000 = 0 */
    ASSERT_EQ(15, bit_reader_read(&br, 4));   /* 1111 = 15 */
}

TEST(bit_reader_skip_and_read) {
    uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    bit_reader_skip(&br, 16);  /* Skip first two bytes */
    ASSERT_EQ(16, bit_reader_remaining(&br));

    ASSERT_EQ(0xCC, bit_reader_read(&br, 8));
    ASSERT_EQ(0xDD, bit_reader_read(&br, 8));
}

TEST(bit_reader_alternating_bits) {
    uint8_t data[] = {0xAA};  /* 1010 1010 */
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    for (int i = 0; i < 4; i++) {
        ASSERT_EQ(1, bit_reader_read(&br, 1));
        ASSERT_EQ(0, bit_reader_read(&br, 1));
    }
}

TEST(bit_reader_all_zeros) {
    uint8_t data[] = {0x00, 0x00, 0x00, 0x00};
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    ASSERT_EQ(0, bit_reader_read(&br, 32));
}

TEST(bit_reader_all_ones) {
    uint8_t data[] = {0xFF, 0xFF, 0xFF, 0xFF};
    bit_reader_t br;

    bit_reader_init(&br, data, sizeof(data));

    ASSERT_EQ(0xFFFFFFFF, bit_reader_read(&br, 32));
}

TEST(bit_reader_empty) {
    bit_reader_t br;

    bit_reader_init(&br, NULL, 0);

    ASSERT_EQ(0, bit_reader_remaining(&br));
    ASSERT_FALSE(bit_reader_has_bits(&br, 1));
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_bit_reader_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== Bit Reader Tests ===" ANSI_RESET "\n");

    RUN_TEST(bit_reader_cross_byte_read);
    RUN_TEST(bit_reader_single_byte);
    RUN_TEST(bit_reader_read_32_bits);
    RUN_TEST(bit_reader_mixed_reads);
    RUN_TEST(bit_reader_skip_and_read);
    RUN_TEST(bit_reader_alternating_bits);
    RUN_TEST(bit_reader_all_zeros);
    RUN_TEST(bit_reader_all_ones);
    RUN_TEST(bit_reader_empty);
}
