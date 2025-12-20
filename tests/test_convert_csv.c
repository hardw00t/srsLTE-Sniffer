/**
 * test_convert_csv.c - Tests for CSV conversion functions
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

/*============================================================================
 * Re-implement key functions from convert_to_csv.c for testing
 *============================================================================*/

static bool is_valid_stmsi(const char *payload, int start, int payload_len) {
    if (start < 0 || start + 10 > payload_len) {
        return false;
    }

    bool has_hex_letter = false;
    for (int i = 0; i < 10; i++) {
        char c = payload[start + i];
        if (!isxdigit(c)) {
            return false;
        }
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            has_hex_letter = true;
        }
    }

    return has_hex_letter;
}

static bool find_imsi(const char *payload, int payload_len, int *imsi_index, int *imsi_length) {
    for (int i = 0; i < payload_len - 16; i++) {
        if (payload[i] == '9' && payload[i + 1] == '5' &&
            !(payload[i + 2] == '0' && payload[i + 3] == '0') &&
            !(payload[i + 4] == '0' && payload[i + 5] == '0') &&
            !(payload[i + 6] == '0' && payload[i + 7] == '0' &&
              payload[i + 8] == '0' && payload[i + 9] == '0')) {

            for (int j = 16; j >= 15; j--) {
                if (i + j < payload_len && payload[i + j] == '8') {
                    bool all_digits = true;
                    for (int k = i + 1; k < i + j; k++) {
                        if (!isdigit(payload[k])) {
                            all_digits = false;
                            break;
                        }
                    }

                    if (all_digits) {
                        *imsi_index = i + 1;
                        *imsi_length = j - 1;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

/*============================================================================
 * Tests
 *============================================================================*/

TEST(find_imsi_basic) {
    const char *payload = "0095250123456789018000";
    int index, length;

    bool found = find_imsi(payload, strlen(payload), &index, &length);
    ASSERT_TRUE(found);
    /* Index is after the '9' marker, pointing to IMSI start */
    ASSERT_TRUE(index >= 2 && index <= 4);
    ASSERT_EQ(15, length);

    /* Extract IMSI */
    char imsi[16] = {0};
    strncpy(imsi, payload + index, length);
    ASSERT_STR_EQ("525012345678901", imsi);
}

TEST(find_imsi_with_prefix) {
    const char *payload = "abcdef95250123456789018end";
    int index, length;

    bool found = find_imsi(payload, strlen(payload), &index, &length);
    ASSERT_TRUE(found);
}

TEST(find_imsi_not_found) {
    const char *payload = "abcdef12345678901234";
    int index, length;

    bool found = find_imsi(payload, strlen(payload), &index, &length);
    ASSERT_FALSE(found);
}

TEST(find_imsi_mcc_validation) {
    /* MCC starting with 500 should fail (payload[i+2]=='0' && payload[i+3]=='0') */
    const char *payload_invalid = "9500012345678901800";
    int index, length;

    bool found = find_imsi(payload_invalid, strlen(payload_invalid), &index, &length);
    ASSERT_FALSE(found);

    /* MCC starting with 501 should pass */
    const char *payload_valid = "95010123456789018";
    found = find_imsi(payload_valid, strlen(payload_valid), &index, &length);
    ASSERT_TRUE(found);
}

TEST(find_imsi_mnc_validation) {
    /* MNC = 00 should fail */
    const char *payload_invalid = "95100012345678901800";
    int index, length;

    /* This pattern has MCC=510, MNC=00, which should fail validation */
    /* Actually the check is for payload[i+4,i+5] != "00" */
    bool found = find_imsi(payload_invalid, strlen(payload_invalid), &index, &length);
    ASSERT_FALSE(found);
}

TEST(is_valid_stmsi_basic) {
    /* Valid S-TMSI: 10 hex chars with at least one a-f */
    ASSERT_TRUE(is_valid_stmsi("ab12345678", 0, 10));
    ASSERT_TRUE(is_valid_stmsi("00AB12CD34", 0, 10));

    /* All digits - likely IMSI fragment */
    ASSERT_FALSE(is_valid_stmsi("1234567890", 0, 10));

    /* Too short */
    ASSERT_FALSE(is_valid_stmsi("ab1234567", 0, 9));

    /* Invalid hex */
    ASSERT_FALSE(is_valid_stmsi("ab1234567g", 0, 10));
}

TEST(is_valid_stmsi_offset) {
    const char *payload = "prefix_ab12345678_suffix";

    ASSERT_TRUE(is_valid_stmsi(payload, 7, strlen(payload)));
    ASSERT_FALSE(is_valid_stmsi(payload, 0, strlen(payload)));
}

TEST(is_valid_stmsi_bounds) {
    ASSERT_FALSE(is_valid_stmsi("ab123", 0, 5));  /* Too short */
    ASSERT_FALSE(is_valid_stmsi("ab12345678", -1, 10));  /* Negative start */
    ASSERT_FALSE(is_valid_stmsi("ab12345678", 5, 10));  /* Would exceed length */
}

TEST(imsi_format_15_digits) {
    const char *payload = "9525012345678901800";
    int index, length;

    bool found = find_imsi(payload, strlen(payload), &index, &length);
    ASSERT_TRUE(found);
    ASSERT_EQ(15, length);
}

TEST(imsi_format_14_digits) {
    const char *payload = "952501234567890800";
    int index, length;

    bool found = find_imsi(payload, strlen(payload), &index, &length);
    ASSERT_TRUE(found);
    ASSERT_EQ(14, length);
}

TEST(combined_imsi_stmsi) {
    /* Payload with S-TMSI before IMSI */
    const char *payload = "ab1234567895250123456789018";
    int index, length;

    bool found = find_imsi(payload, strlen(payload), &index, &length);
    ASSERT_TRUE(found);

    /* Check for S-TMSI before IMSI */
    int stmsi_start = index - 11;  /* 10 chars + 1 for '9' */
    if (stmsi_start >= 0) {
        bool has_stmsi = is_valid_stmsi(payload, stmsi_start, strlen(payload));
        ASSERT_TRUE(has_stmsi);
    }
}

TEST(empty_payload) {
    int index, length;
    bool found = find_imsi("", 0, &index, &length);
    ASSERT_FALSE(found);
}

TEST(short_payload) {
    int index, length;
    bool found = find_imsi("95250", 5, &index, &length);
    ASSERT_FALSE(found);
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_convert_csv_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== CSV Conversion Tests ===" ANSI_RESET "\n");

    RUN_TEST(find_imsi_basic);
    RUN_TEST(find_imsi_with_prefix);
    RUN_TEST(find_imsi_not_found);
    RUN_TEST(find_imsi_mcc_validation);
    RUN_TEST(find_imsi_mnc_validation);
    RUN_TEST(is_valid_stmsi_basic);
    RUN_TEST(is_valid_stmsi_offset);
    RUN_TEST(is_valid_stmsi_bounds);
    RUN_TEST(imsi_format_15_digits);
    RUN_TEST(imsi_format_14_digits);
    RUN_TEST(combined_imsi_stmsi);
    RUN_TEST(empty_payload);
    RUN_TEST(short_payload);
}
