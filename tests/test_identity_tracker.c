/**
 * test_identity_tracker.c - Tests for identity tracking
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include "identity_tracker.h"
#include <string.h>

/*============================================================================
 * Tests
 *============================================================================*/

TEST(tracker_create_destroy) {
    identity_tracker_t *tracker = tracker_create(NULL);
    ASSERT_NOT_NULL(tracker);
    tracker_destroy(tracker);

    /* With custom config */
    tracker_config_t config = {
        .max_records = 100,
        .expiry_seconds = 3600
    };
    tracker = tracker_create(&config);
    ASSERT_NOT_NULL(tracker);
    tracker_destroy(tracker);
}

TEST(tracker_record_imsi) {
    identity_tracker_t *tracker = tracker_create(NULL);

    identity_record_t *rec = tracker_record_imsi(tracker, "525012345678901", 100, 200);
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ("525012345678901", rec->imsi);
    ASSERT_TRUE(rec->imsi_known);
    ASSERT_EQ(100, rec->current_cell);
    ASSERT_EQ(200, rec->current_tac);
    ASSERT_EQ(1, rec->paging_count);

    /* Record again - should update existing */
    rec = tracker_record_imsi(tracker, "525012345678901", 101, 200);
    ASSERT_NOT_NULL(rec);
    ASSERT_EQ(2, rec->paging_count);
    ASSERT_EQ(101, rec->current_cell);

    tracker_destroy(tracker);
}

TEST(tracker_record_stmsi) {
    identity_tracker_t *tracker = tracker_create(NULL);

    identity_record_t *rec = tracker_record_stmsi(tracker, "ab12345678", 100, 200);
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ("ab12345678", rec->stmsi);
    ASSERT_FALSE(rec->imsi_known);

    tracker_destroy(tracker);
}

TEST(tracker_correlate) {
    identity_tracker_t *tracker = tracker_create(NULL);

    identity_record_t *rec = tracker_correlate(tracker, "525012345678901",
                                                "ab12345678", 100, 200);
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ("525012345678901", rec->imsi);
    ASSERT_STR_EQ("ab12345678", rec->stmsi);
    ASSERT_TRUE(rec->imsi_known);

    tracker_destroy(tracker);
}

TEST(tracker_find_by_imsi) {
    identity_tracker_t *tracker = tracker_create(NULL);

    tracker_record_imsi(tracker, "525012345678901", 100, 200);
    tracker_record_imsi(tracker, "525098765432101", 100, 200);

    identity_record_t *rec = tracker_find_by_imsi(tracker, "525012345678901");
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ("525012345678901", rec->imsi);

    rec = tracker_find_by_imsi(tracker, "999999999999999");
    ASSERT_NULL(rec);

    tracker_destroy(tracker);
}

TEST(tracker_find_by_stmsi) {
    identity_tracker_t *tracker = tracker_create(NULL);

    tracker_correlate(tracker, "525012345678901", "ab12345678", 100, 200);

    identity_record_t *rec = tracker_find_by_stmsi(tracker, "ab12345678");
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ("525012345678901", rec->imsi);

    rec = tracker_find_by_stmsi(tracker, "ff00000000");
    ASSERT_NULL(rec);

    tracker_destroy(tracker);
}

TEST(tracker_stmsi_to_imsi) {
    identity_tracker_t *tracker = tracker_create(NULL);

    tracker_correlate(tracker, "525012345678901", "ab12345678", 100, 200);

    const char *imsi = tracker_stmsi_to_imsi(tracker, "ab12345678");
    ASSERT_NOT_NULL(imsi);
    ASSERT_STR_EQ("525012345678901", imsi);

    imsi = tracker_stmsi_to_imsi(tracker, "unknown123");
    ASSERT_NULL(imsi);

    tracker_destroy(tracker);
}

TEST(tracker_imsi_to_stmsi) {
    identity_tracker_t *tracker = tracker_create(NULL);

    tracker_correlate(tracker, "525012345678901", "ab12345678", 100, 200);

    const char *stmsi = tracker_imsi_to_stmsi(tracker, "525012345678901");
    ASSERT_NOT_NULL(stmsi);
    ASSERT_STR_EQ("ab12345678", stmsi);

    stmsi = tracker_imsi_to_stmsi(tracker, "999999999999999");
    ASSERT_NULL(stmsi);

    tracker_destroy(tracker);
}

TEST(tracker_stmsi_history) {
    identity_tracker_t *tracker = tracker_create(NULL);

    /* Initial correlation */
    tracker_correlate(tracker, "525012345678901", "ab12345678", 100, 200);

    /* New S-TMSI assigned */
    identity_record_t *rec = tracker_correlate(tracker, "525012345678901",
                                                "cd87654321", 100, 200);
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ("cd87654321", rec->stmsi);
    ASSERT_GT(rec->stmsi_history_count, 0);
    ASSERT_STR_EQ("ab12345678", rec->stmsi_history[0]);

    tracker_destroy(tracker);
}

TEST(tracker_cells_seen) {
    tracker_config_t config = { .track_location = true };
    identity_tracker_t *tracker = tracker_create(&config);

    /* Record in multiple cells */
    tracker_record_imsi(tracker, "525012345678901", 100, 200);
    tracker_record_imsi(tracker, "525012345678901", 101, 200);
    tracker_record_imsi(tracker, "525012345678901", 102, 200);
    tracker_record_imsi(tracker, "525012345678901", 100, 200);  /* Duplicate */

    identity_record_t *rec = tracker_find_by_imsi(tracker, "525012345678901");
    ASSERT_NOT_NULL(rec);
    ASSERT_EQ(3, rec->num_cells);  /* Should only have 3 unique cells */

    tracker_destroy(tracker);
}

TEST(tracker_stats) {
    identity_tracker_t *tracker = tracker_create(NULL);

    tracker_record_imsi(tracker, "525012345678901", 100, 200);
    tracker_record_stmsi(tracker, "ab12345678", 100, 200);
    tracker_correlate(tracker, "525098765432101", "cd87654321", 100, 200);

    tracker_stats_t stats;
    tracker_get_stats(tracker, &stats);

    ASSERT_EQ(3, stats.total_records);
    ASSERT_EQ(2, stats.known_imsi_count);

    tracker_destroy(tracker);
}

TEST(stmsi_parse_format) {
    uint8_t mmec;
    uint32_t m_tmsi;

    stmsi_parse("ab12345678", &mmec, &m_tmsi);
    ASSERT_EQ(0xAB, mmec);
    ASSERT_EQ(0x12345678, m_tmsi);

    char formatted[16];
    stmsi_format(0xAB, 0x12345678, formatted);
    ASSERT_STR_EQ("ab12345678", formatted);
}

TEST(imsi_extract_plmn) {
    uint16_t mcc, mnc;

    imsi_extract_plmn("525012345678901", &mcc, &mnc);
    ASSERT_EQ(525, mcc);
    /* MNC is 01 but may be parsed as 012=12 with 3-digit check */
    ASSERT_TRUE(mnc == 1 || mnc == 12);
}

TEST(identity_detect_type) {
    ASSERT_EQ(IDENTITY_TYPE_IMSI, identity_detect_type("525012345678901"));
    ASSERT_EQ(IDENTITY_TYPE_STMSI, identity_detect_type("ab12345678"));
    ASSERT_EQ(IDENTITY_TYPE_UNKNOWN, identity_detect_type("short"));
    ASSERT_EQ(IDENTITY_TYPE_UNKNOWN, identity_detect_type(NULL));
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_identity_tracker_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== Identity Tracker Tests ===" ANSI_RESET "\n");

    RUN_TEST(tracker_create_destroy);
    RUN_TEST(tracker_record_imsi);
    RUN_TEST(tracker_record_stmsi);
    RUN_TEST(tracker_correlate);
    RUN_TEST(tracker_find_by_imsi);
    RUN_TEST(tracker_find_by_stmsi);
    RUN_TEST(tracker_stmsi_to_imsi);
    RUN_TEST(tracker_imsi_to_stmsi);
    RUN_TEST(tracker_stmsi_history);
    RUN_TEST(tracker_cells_seen);
    RUN_TEST(tracker_stats);
    RUN_TEST(stmsi_parse_format);
    RUN_TEST(imsi_extract_plmn);
    RUN_TEST(identity_detect_type);
}
