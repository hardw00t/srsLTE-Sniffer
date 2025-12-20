/**
 * test_data_handler.c - Tests for data handler infrastructure
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include "data_handler.h"
#include <string.h>

/*============================================================================
 * Test Callback State
 *============================================================================*/

static int g_callback_count = 0;
static decoded_data_t g_last_data;

static void test_callback(const decoded_data_t *data, void *ctx) {
    (void)ctx;
    g_callback_count++;
    if (data) {
        memcpy(&g_last_data, data, sizeof(decoded_data_t));
    }
}

static void reset_callback_state(void) {
    g_callback_count = 0;
    memset(&g_last_data, 0, sizeof(g_last_data));
}

/*============================================================================
 * Tests
 *============================================================================*/

TEST(handler_init_shutdown) {
    ASSERT_EQ(0, data_handler_init());
    data_handler_shutdown();

    /* Should be safe to call multiple times */
    data_handler_shutdown();
}

TEST(handler_register_callback) {
    data_handler_init();

    int id = data_handler_register(DATA_TYPE_PAGING, test_callback, NULL, "test");
    ASSERT_GE(id, 0);

    data_handler_shutdown();
}

TEST(handler_register_global) {
    data_handler_init();

    int id = data_handler_register_global(test_callback, NULL, "global_test");
    ASSERT_GE(id, 0);

    data_handler_shutdown();
}

TEST(handler_process_calls_callback) {
    reset_callback_state();
    data_handler_init();

    int id = data_handler_register(DATA_TYPE_PAGING, test_callback, NULL, "test");
    ASSERT_GE(id, 0);

    decoded_data_t data = {
        .type = DATA_TYPE_PAGING,
        .sfn = 123,
        .sfidx = 5,
        .rnti = 0x1234
    };

    data_handler_process(&data);

    ASSERT_EQ(1, g_callback_count);
    ASSERT_EQ(DATA_TYPE_PAGING, g_last_data.type);
    ASSERT_EQ(123, g_last_data.sfn);
    ASSERT_EQ(5, g_last_data.sfidx);
    ASSERT_EQ(0x1234, g_last_data.rnti);

    data_handler_shutdown();
}

TEST(handler_global_receives_all_types) {
    reset_callback_state();
    data_handler_init();

    data_handler_register_global(test_callback, NULL, "global");

    decoded_data_t data1 = { .type = DATA_TYPE_PAGING };
    decoded_data_t data2 = { .type = DATA_TYPE_SIB1 };
    decoded_data_t data3 = { .type = DATA_TYPE_SIB2 };

    data_handler_process(&data1);
    data_handler_process(&data2);
    data_handler_process(&data3);

    ASSERT_EQ(3, g_callback_count);

    data_handler_shutdown();
}

TEST(handler_type_specific_filtering) {
    reset_callback_state();
    data_handler_init();

    data_handler_register(DATA_TYPE_SIB1, test_callback, NULL, "sib1_only");

    decoded_data_t paging = { .type = DATA_TYPE_PAGING };
    decoded_data_t sib1 = { .type = DATA_TYPE_SIB1 };

    data_handler_process(&paging);
    ASSERT_EQ(0, g_callback_count);  /* Should not be called for paging */

    data_handler_process(&sib1);
    ASSERT_EQ(1, g_callback_count);  /* Should be called for SIB1 */

    data_handler_shutdown();
}

TEST(handler_enable_disable) {
    reset_callback_state();
    data_handler_init();

    int id = data_handler_register(DATA_TYPE_PAGING, test_callback, NULL, "test");

    decoded_data_t data = { .type = DATA_TYPE_PAGING };

    data_handler_process(&data);
    ASSERT_EQ(1, g_callback_count);

    /* Disable handler */
    data_handler_set_enabled(DATA_TYPE_PAGING, id, false);
    data_handler_process(&data);
    ASSERT_EQ(1, g_callback_count);  /* Should not increase */

    /* Re-enable handler */
    data_handler_set_enabled(DATA_TYPE_PAGING, id, true);
    data_handler_process(&data);
    ASSERT_EQ(2, g_callback_count);  /* Should increase */

    data_handler_shutdown();
}

TEST(handler_unregister) {
    reset_callback_state();
    data_handler_init();

    int id = data_handler_register(DATA_TYPE_PAGING, test_callback, NULL, "test");

    decoded_data_t data = { .type = DATA_TYPE_PAGING };
    data_handler_process(&data);
    ASSERT_EQ(1, g_callback_count);

    /* Unregister */
    ASSERT_EQ(0, data_handler_unregister(DATA_TYPE_PAGING, id));

    data_handler_process(&data);
    ASSERT_EQ(1, g_callback_count);  /* Should not increase */

    data_handler_shutdown();
}

TEST(handler_null_data_safe) {
    data_handler_init();

    data_handler_register(DATA_TYPE_PAGING, test_callback, NULL, "test");

    /* Should not crash */
    data_handler_process(NULL);

    data_handler_shutdown();
}

TEST(data_type_names_valid) {
    ASSERT_NOT_NULL(data_type_names[DATA_TYPE_PAGING]);
    ASSERT_NOT_NULL(data_type_names[DATA_TYPE_SIB1]);
    ASSERT_NOT_NULL(data_type_names[DATA_TYPE_SIB2]);
    ASSERT_NOT_NULL(data_type_names[DATA_TYPE_MIB]);
    ASSERT_NOT_NULL(data_type_names[DATA_TYPE_OTHER]);

    ASSERT_STR_EQ("PAGING", data_type_names[DATA_TYPE_PAGING]);
    ASSERT_STR_EQ("SIB1", data_type_names[DATA_TYPE_SIB1]);
}

TEST(rsrp_snr_conversion) {
    /* Test RSRP conversion */
    float rsrp_linear = 0.001f;  /* Very weak signal */
    float rsrp_dbm = rsrp_to_dbm(rsrp_linear);
    ASSERT_TRUE(rsrp_dbm < 1);  /* Should be negative or near zero dBm */

    /* Test SNR conversion */
    float snr_linear = 10.0f;  /* 10 dB SNR in linear */
    float snr_db = snr_to_db(snr_linear);
    ASSERT_FLOAT_EQ(10.0, snr_db, 0.1);
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_data_handler_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== Data Handler Tests ===" ANSI_RESET "\n");

    RUN_TEST(handler_init_shutdown);
    RUN_TEST(handler_register_callback);
    RUN_TEST(handler_register_global);
    RUN_TEST(handler_process_calls_callback);
    RUN_TEST(handler_global_receives_all_types);
    RUN_TEST(handler_type_specific_filtering);
    RUN_TEST(handler_enable_disable);
    RUN_TEST(handler_unregister);
    RUN_TEST(handler_null_data_safe);
    RUN_TEST(data_type_names_valid);
    RUN_TEST(rsrp_snr_conversion);
}
