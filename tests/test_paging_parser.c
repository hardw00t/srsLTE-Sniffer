/**
 * test_paging_parser.c - Tests for paging message parsing functions
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include "paging_parser.h"
#include <string.h>

/*============================================================================
 * Test Data
 *============================================================================*/

/* S-TMSI test data */
static const char *test_stmsi_hex = "ab12345678";
static const uint8_t test_stmsi_bytes[] = {0xAB, 0x12, 0x34, 0x56, 0x78};

/* IMSI test data (BCD encoded) */
/* IMSI: 525012345678901 (MCC=525, MNC=01) */
static const uint8_t test_imsi_bcd[] = {
    0x59,  /* Type + digit 5 */
    0x52,  /* digits 2, 5 */
    0x10,  /* digits 0, 1 */
    0x32,  /* digits 2, 3 */
    0x54,  /* digits 4, 5 */
    0x76,  /* digits 6, 7 */
    0x98,  /* digits 8, 9 */
    0x10   /* digits 0, 1 */
};

/* Heuristic test payloads */
/* Contains IMSI pattern: "95250123456789018" */
static const uint8_t heuristic_imsi_payload[] = {
    0x00, 0x01, 0x95, 0x25, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x80, 0x00
};

/* Contains S-TMSI pattern with hex letters.
 * Start directly with S-TMSI bytes so heuristic finds them at position 0.
 * S-TMSI "ab12345678" = MMEC 0xAB, M-TMSI 0x12345678 */
static const uint8_t heuristic_stmsi_payload[] = {
    0xab, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00
};

/*============================================================================
 * S-TMSI Tests
 *============================================================================*/

TEST(stmsi_parse_basic) {
    stmsi_t stmsi;

    int result = paging_parse_stmsi(test_stmsi_bytes, &stmsi);
    ASSERT_EQ(0, result);
    ASSERT_EQ(0xAB, stmsi.mmec);
    ASSERT_EQ(0x12345678, stmsi.m_tmsi);
}

TEST(stmsi_format) {
    stmsi_t stmsi;
    char buf[16];

    stmsi.mmec = 0xAB;
    stmsi.m_tmsi = 0x12345678;

    paging_stmsi_to_hex(&stmsi, buf);
    ASSERT_STR_EQ("ab12345678", buf);
}

TEST(stmsi_from_hex) {
    stmsi_t stmsi;

    int result = paging_stmsi_from_hex("ab12345678", &stmsi);
    ASSERT_EQ(0, result);
    ASSERT_EQ(0xAB, stmsi.mmec);
    ASSERT_EQ(0x12345678, stmsi.m_tmsi);
    ASSERT_STR_EQ("ab12345678", stmsi.hex_str);
}

TEST(stmsi_from_hex_uppercase) {
    stmsi_t stmsi;

    int result = paging_stmsi_from_hex("AB12345678", &stmsi);
    ASSERT_EQ(0, result);
    ASSERT_EQ(0xAB, stmsi.mmec);
    /* Stored in lowercase */
    ASSERT_STR_EQ("ab12345678", stmsi.hex_str);
}

TEST(stmsi_from_hex_invalid) {
    stmsi_t stmsi;

    /* Too short */
    ASSERT_EQ(-1, paging_stmsi_from_hex("ab123456", &stmsi));

    /* Too long */
    ASSERT_EQ(-1, paging_stmsi_from_hex("ab1234567890", &stmsi));

    /* Invalid characters */
    ASSERT_EQ(-1, paging_stmsi_from_hex("ab123456gh", &stmsi));

    /* NULL */
    ASSERT_EQ(-1, paging_stmsi_from_hex(NULL, &stmsi));
}

/*============================================================================
 * IMSI Tests
 *============================================================================*/

TEST(imsi_parse_basic) {
    imsi_t imsi;

    int result = paging_parse_imsi(test_imsi_bcd, sizeof(test_imsi_bcd), &imsi);
    ASSERT_EQ(0, result);
    ASSERT_TRUE(imsi.length >= 14);
}

TEST(imsi_extract_plmn) {
    imsi_t imsi;

    /* Set up test IMSI */
    strcpy(imsi.digits, "525012345678901");
    imsi.length = 15;
    imsi.mcc = 525;
    imsi.mnc = 1;

    uint16_t mcc, mnc;
    paging_extract_plmn(&imsi, &mcc, &mnc);

    ASSERT_EQ(525, mcc);
    ASSERT_EQ(1, mnc);
}

/*============================================================================
 * Heuristic Parsing Tests
 *============================================================================*/

TEST(heuristic_find_imsi) {
    imsi_t imsi;

    int result = paging_find_imsi_heuristic(heuristic_imsi_payload,
                                             sizeof(heuristic_imsi_payload),
                                             &imsi);
    ASSERT_EQ(0, result);
    ASSERT_EQ(15, imsi.length);
    ASSERT_STR_EQ("525012345678901", imsi.digits);
    ASSERT_EQ(525, imsi.mcc);
}

TEST(heuristic_find_stmsi) {
    stmsi_t stmsi;

    int result = paging_find_stmsi_heuristic(heuristic_stmsi_payload,
                                              sizeof(heuristic_stmsi_payload),
                                              &stmsi);
    ASSERT_EQ(0, result);
    ASSERT_EQ(0xAB, stmsi.mmec);
    ASSERT_EQ(0x12345678, stmsi.m_tmsi);
}

TEST(heuristic_no_imsi) {
    imsi_t imsi;
    uint8_t no_imsi[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};

    int result = paging_find_imsi_heuristic(no_imsi, sizeof(no_imsi), &imsi);
    ASSERT_EQ(-1, result);
}

TEST(heuristic_no_stmsi) {
    stmsi_t stmsi;
    /* All digits - no hex letters, so not S-TMSI */
    uint8_t no_stmsi[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0x12};

    int result = paging_find_stmsi_heuristic(no_stmsi, sizeof(no_stmsi), &stmsi);
    ASSERT_EQ(-1, result);
}

/*============================================================================
 * Paging Message Parsing Tests
 *============================================================================*/

TEST(paging_parse_empty) {
    paging_message_t msg;

    int result = paging_parse(NULL, 0, &msg);
    ASSERT_EQ(-1, result);
}

TEST(paging_parse_with_context) {
    paging_message_t msg;

    int result = paging_parse_with_context(
        heuristic_imsi_payload,
        sizeof(heuristic_imsi_payload),
        512, 5, 123,
        &msg
    );

    /* Should find IMSI via heuristic */
    ASSERT_TRUE(result == 0 || msg.num_records > 0);
    ASSERT_EQ(512, msg.sfn);
    ASSERT_EQ(5, msg.subframe);
    ASSERT_EQ(123, msg.cell_id);
}

/*============================================================================
 * String Function Tests
 *============================================================================*/

TEST(paging_cause_str) {
    ASSERT_STR_EQ("Unspecified", paging_cause_str(PAGING_CAUSE_UNSPECIFIED));
    ASSERT_STR_EQ("Voice Call", paging_cause_str(PAGING_CAUSE_VOICE));
    ASSERT_STR_EQ("SMS", paging_cause_str(PAGING_CAUSE_SMS));
}

TEST(paging_id_type_str) {
    ASSERT_STR_EQ("S-TMSI", paging_id_type_str(PAGING_ID_STMSI));
    ASSERT_STR_EQ("IMSI", paging_id_type_str(PAGING_ID_IMSI));
}

/*============================================================================
 * JSON Output Tests
 *============================================================================*/

TEST(paging_to_json_empty) {
    paging_message_t msg;
    char buf[256];

    memset(&msg, 0, sizeof(msg));
    msg.valid = false;

    int len = paging_to_json(&msg, buf, sizeof(buf));
    ASSERT_GT(len, 0);
    ASSERT_TRUE(strstr(buf, "\"valid\":false") != NULL);
}

TEST(paging_to_json_with_records) {
    paging_message_t msg;
    char buf[512];

    memset(&msg, 0, sizeof(msg));
    msg.valid = true;
    msg.sfn = 100;
    msg.subframe = 5;
    msg.cell_id = 123;
    msg.num_records = 1;
    msg.num_imsi = 1;

    msg.records[0].id_type = PAGING_ID_IMSI;
    strcpy(msg.records[0].imsi.digits, "525012345678901");
    msg.records[0].imsi.mcc = 525;
    msg.records[0].imsi.mnc = 1;

    int len = paging_to_json(&msg, buf, sizeof(buf));
    ASSERT_GT(len, 0);
    ASSERT_TRUE(strstr(buf, "\"type\":\"PAGING\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"sfn\":100") != NULL);
    ASSERT_TRUE(strstr(buf, "\"num_imsi\":1") != NULL);
    ASSERT_TRUE(strstr(buf, "\"valid\":true") != NULL);
}

/*============================================================================
 * Null Safety Tests
 *============================================================================*/

TEST(paging_null_safety) {
    paging_message_t msg;
    stmsi_t stmsi;
    imsi_t imsi;
    char buf[64];

    /* NULL payload */
    ASSERT_EQ(-1, paging_parse(NULL, 10, &msg));

    /* NULL output */
    uint8_t data[] = {0x01, 0x02};
    ASSERT_EQ(-1, paging_parse(data, 2, NULL));

    /* NULL in heuristic functions */
    ASSERT_EQ(-1, paging_find_imsi_heuristic(NULL, 10, &imsi));
    ASSERT_EQ(-1, paging_find_stmsi_heuristic(NULL, 10, &stmsi));

    /* NULL in format functions */
    paging_stmsi_to_hex(NULL, buf);  /* Should not crash */
    ASSERT_EQ(-1, paging_stmsi_from_hex(NULL, &stmsi));
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_paging_parser_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== Paging Parser Tests ===" ANSI_RESET "\n");

    RUN_TEST(stmsi_parse_basic);
    RUN_TEST(stmsi_format);
    RUN_TEST(stmsi_from_hex);
    RUN_TEST(stmsi_from_hex_uppercase);
    RUN_TEST(stmsi_from_hex_invalid);
    RUN_TEST(imsi_parse_basic);
    RUN_TEST(imsi_extract_plmn);
    RUN_TEST(heuristic_find_imsi);
    RUN_TEST(heuristic_find_stmsi);
    RUN_TEST(heuristic_no_imsi);
    RUN_TEST(heuristic_no_stmsi);
    RUN_TEST(paging_parse_empty);
    RUN_TEST(paging_parse_with_context);
    RUN_TEST(paging_cause_str);
    RUN_TEST(paging_id_type_str);
    RUN_TEST(paging_to_json_empty);
    RUN_TEST(paging_to_json_with_records);
    RUN_TEST(paging_null_safety);
}
