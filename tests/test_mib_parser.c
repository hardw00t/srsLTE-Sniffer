/**
 * test_mib_parser.c - Tests for MIB parsing functions
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include "mib_parser.h"
#include <string.h>

/*============================================================================
 * Test Data
 *============================================================================*/

/* Sample MIB payloads (24 bits = 3 bytes) */

/* MIB: 20 MHz (100 RBs), Normal PHICH, Ng=1, SFN=0 */
static const uint8_t mib_20mhz[] = {0xA8, 0x00, 0x00};

/* MIB: 10 MHz (50 RBs), Normal PHICH, Ng=1/2, SFN=0
 * Byte 0: [011][0][01][00] = 0x64 (BW=3, PHICH_D=0, PHICH_R=1, SFN[7:6]=0) */
static const uint8_t mib_10mhz[] = {0x64, 0x00, 0x00};

/* MIB: 5 MHz (25 RBs), Extended PHICH, Ng=2, SFN=512
 * Byte 0: [010][1][11][10] = 0x5E (BW=2, PHICH_D=1, PHICH_R=3, SFN[7:6]=2)
 * sfn_high = (10 << 6) | 0 = 128, info.sfn = 128 << 2 = 512 */
static const uint8_t mib_5mhz[] = {0x5E, 0x00, 0x00};

/* MIB: 1.4 MHz (6 RBs), Normal PHICH, Ng=1/6, SFN=1020 */
static const uint8_t mib_1_4mhz[] = {0x00, 0x3F, 0xC0};

/*============================================================================
 * Tests
 *============================================================================*/

TEST(mib_parse_basic) {
    mib_info_t info;

    int result = mib_parse(mib_20mhz, &info);
    ASSERT_EQ(0, result);
    ASSERT_TRUE(info.valid);
    ASSERT_EQ(DL_BANDWIDTH_100, info.dl_bandwidth);
    ASSERT_EQ(100, info.n_rb_dl);
    ASSERT_FLOAT_EQ(20.0f, info.bandwidth_mhz, 0.1f);
}

TEST(mib_parse_phich_normal) {
    mib_info_t info;

    mib_parse(mib_20mhz, &info);
    ASSERT_EQ(PHICH_DURATION_NORMAL, info.phich_duration);
}

TEST(mib_parse_phich_extended) {
    mib_info_t info;

    mib_parse(mib_5mhz, &info);
    ASSERT_EQ(PHICH_DURATION_EXTENDED, info.phich_duration);
}

TEST(mib_parse_phich_resource) {
    mib_info_t info;

    /* 20 MHz has Ng=1 */
    mib_parse(mib_20mhz, &info);
    ASSERT_EQ(PHICH_RESOURCE_ONE, info.phich_resource);
    ASSERT_FLOAT_EQ(1.0f, info.phich_ng, 0.01f);

    /* 10 MHz has Ng=1/2 */
    mib_parse(mib_10mhz, &info);
    ASSERT_EQ(PHICH_RESOURCE_HALF, info.phich_resource);
    ASSERT_FLOAT_EQ(0.5f, info.phich_ng, 0.01f);

    /* 5 MHz has Ng=2 */
    mib_parse(mib_5mhz, &info);
    ASSERT_EQ(PHICH_RESOURCE_TWO, info.phich_resource);
    ASSERT_FLOAT_EQ(2.0f, info.phich_ng, 0.01f);
}

TEST(mib_parse_bandwidth_values) {
    mib_info_t info;

    /* 20 MHz */
    mib_parse(mib_20mhz, &info);
    ASSERT_EQ(DL_BANDWIDTH_100, info.dl_bandwidth);
    ASSERT_EQ(100, info.n_rb_dl);

    /* 10 MHz */
    mib_parse(mib_10mhz, &info);
    ASSERT_EQ(DL_BANDWIDTH_50, info.dl_bandwidth);
    ASSERT_EQ(50, info.n_rb_dl);

    /* 5 MHz */
    mib_parse(mib_5mhz, &info);
    ASSERT_EQ(DL_BANDWIDTH_25, info.dl_bandwidth);
    ASSERT_EQ(25, info.n_rb_dl);

    /* 1.4 MHz */
    mib_parse(mib_1_4mhz, &info);
    ASSERT_EQ(DL_BANDWIDTH_6, info.dl_bandwidth);
    ASSERT_EQ(6, info.n_rb_dl);
}

TEST(mib_parse_sfn) {
    mib_info_t info;

    /* SFN=0 */
    mib_parse(mib_20mhz, &info);
    /* SFN is constructed from 8 bits in MIB + 2 bits offset */
    uint16_t sfn_from_mib = (info.sfn >> 2);  /* Upper 8 bits */
    ASSERT_EQ(0, sfn_from_mib);

    /* SFN=512 (0x200) -> upper 8 bits = 0x80 = 128 */
    mib_parse(mib_5mhz, &info);
    sfn_from_mib = (info.sfn >> 2);
    ASSERT_EQ(128, sfn_from_mib);
}

TEST(mib_parse_with_context) {
    mib_info_t info;

    int result = mib_parse_with_context(mib_10mhz, 2, 4, 123, &info);
    ASSERT_EQ(0, result);
    ASSERT_TRUE(info.valid);
    ASSERT_EQ(4, info.nof_ports);
    ASSERT_EQ(123, info.pci);
    ASSERT_EQ(2, info.sfn_offset);
}

TEST(mib_parse_null_safety) {
    mib_info_t info;

    ASSERT_EQ(-1, mib_parse(NULL, &info));
    ASSERT_EQ(-1, mib_parse(mib_20mhz, NULL));
    ASSERT_EQ(-1, mib_parse(NULL, NULL));
}

TEST(mib_phich_groups_calculation) {
    /* For 100 RBs, Ng=1: ceil(1.0 * 100 / 8) = 13 */
    ASSERT_EQ(13, mib_calc_phich_groups(100, 1.0f));

    /* For 50 RBs, Ng=0.5: ceil(0.5 * 50 / 8) = 4 */
    ASSERT_EQ(4, mib_calc_phich_groups(50, 0.5f));

    /* For 25 RBs, Ng=2: ceil(2.0 * 25 / 8) = 7 */
    ASSERT_EQ(7, mib_calc_phich_groups(25, 2.0f));

    /* For 6 RBs, Ng=1/6: ceil(0.167 * 6 / 8) = 1 */
    ASSERT_EQ(1, mib_calc_phich_groups(6, 1.0f/6.0f));
}

TEST(mib_utility_functions) {
    /* Bandwidth to MHz */
    ASSERT_FLOAT_EQ(1.4f, mib_bandwidth_to_mhz(DL_BANDWIDTH_6), 0.1f);
    ASSERT_FLOAT_EQ(20.0f, mib_bandwidth_to_mhz(DL_BANDWIDTH_100), 0.1f);

    /* Bandwidth to NRB */
    ASSERT_EQ(6, mib_bandwidth_to_nrb(DL_BANDWIDTH_6));
    ASSERT_EQ(100, mib_bandwidth_to_nrb(DL_BANDWIDTH_100));

    /* PHICH resource to Ng */
    ASSERT_FLOAT_EQ(1.0f/6.0f, mib_phich_resource_to_ng(PHICH_RESOURCE_ONESIXTH), 0.01f);
    ASSERT_FLOAT_EQ(2.0f, mib_phich_resource_to_ng(PHICH_RESOURCE_TWO), 0.01f);
}

TEST(mib_string_functions) {
    /* Bandwidth strings */
    ASSERT_NOT_NULL(mib_bandwidth_str(DL_BANDWIDTH_6));
    ASSERT_NOT_NULL(mib_bandwidth_str(DL_BANDWIDTH_100));

    /* PHICH duration strings */
    ASSERT_STR_EQ("Normal", mib_phich_duration_str(PHICH_DURATION_NORMAL));
    ASSERT_STR_EQ("Extended", mib_phich_duration_str(PHICH_DURATION_EXTENDED));

    /* PHICH resource strings */
    ASSERT_STR_EQ("1/6", mib_phich_resource_str(PHICH_RESOURCE_ONESIXTH));
    ASSERT_STR_EQ("2", mib_phich_resource_str(PHICH_RESOURCE_TWO));
}

TEST(mib_to_json) {
    mib_info_t info;
    char buf[512];

    mib_parse_with_context(mib_20mhz, 0, 4, 123, &info);

    int len = mib_to_json(&info, buf, sizeof(buf));
    ASSERT_GT(len, 0);
    ASSERT_TRUE(strstr(buf, "\"type\":\"MIB\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"pci\":123") != NULL);
    ASSERT_TRUE(strstr(buf, "\"n_rb_dl\":100") != NULL);
    ASSERT_TRUE(strstr(buf, "\"valid\":true") != NULL);
}

TEST(mib_to_json_invalid) {
    mib_info_t info;
    char buf[128];

    memset(&info, 0, sizeof(info));
    info.valid = false;

    int len = mib_to_json(&info, buf, sizeof(buf));
    ASSERT_GT(len, 0);
    ASSERT_TRUE(strstr(buf, "\"valid\":false") != NULL);
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_mib_parser_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== MIB Parser Tests ===" ANSI_RESET "\n");

    RUN_TEST(mib_parse_basic);
    RUN_TEST(mib_parse_phich_normal);
    RUN_TEST(mib_parse_phich_extended);
    RUN_TEST(mib_parse_phich_resource);
    RUN_TEST(mib_parse_bandwidth_values);
    RUN_TEST(mib_parse_sfn);
    RUN_TEST(mib_parse_with_context);
    RUN_TEST(mib_parse_null_safety);
    RUN_TEST(mib_phich_groups_calculation);
    RUN_TEST(mib_utility_functions);
    RUN_TEST(mib_string_functions);
    RUN_TEST(mib_to_json);
    RUN_TEST(mib_to_json_invalid);
}
