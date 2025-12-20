/**
 * test_memory_pool.c - Tests for memory pool allocator
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "test_framework.h"
#include "memory_pool.h"
#include <string.h>

/*============================================================================
 * Tests
 *============================================================================*/

TEST(pool_create_destroy) {
    pool_config_t config = {
        .block_size = 64,
        .initial_blocks = 16,
        .max_blocks = 0,
        .zero_on_alloc = false,
        .thread_safe = false
    };

    memory_pool_t *pool = pool_create(&config);
    ASSERT_NOT_NULL(pool);

    pool_destroy(pool);
}

TEST(pool_create_default) {
    memory_pool_t *pool = pool_create_default(POOL_DECODED_DATA);
    ASSERT_NOT_NULL(pool);
    pool_destroy(pool);

    pool = pool_create_default(POOL_PAYLOAD_SMALL);
    ASSERT_NOT_NULL(pool);
    pool_destroy(pool);
}

TEST(pool_alloc_free) {
    pool_config_t config = {
        .block_size = 64,
        .initial_blocks = 16,
        .max_blocks = 0,
        .zero_on_alloc = true,
        .thread_safe = true
    };

    memory_pool_t *pool = pool_create(&config);

    void *ptr1 = pool_alloc(pool);
    ASSERT_NOT_NULL(ptr1);

    void *ptr2 = pool_alloc(pool);
    ASSERT_NOT_NULL(ptr2);
    ASSERT_NE((long)ptr1, (long)ptr2);

    pool_free(pool, ptr1);
    pool_free(pool, ptr2);

    pool_destroy(pool);
}

TEST(pool_stats) {
    pool_config_t config = {
        .block_size = 64,
        .initial_blocks = 16,
        .max_blocks = 0,
        .zero_on_alloc = false,
        .thread_safe = false
    };

    memory_pool_t *pool = pool_create(&config);

    void *ptr1 = pool_alloc(pool);
    void *ptr2 = pool_alloc(pool);

    pool_stats_t stats;
    pool_get_stats(pool, &stats);

    ASSERT_EQ(16, stats.total_blocks);
    ASSERT_EQ(2, stats.used_blocks);
    ASSERT_EQ(14, stats.free_blocks);
    ASSERT_EQ(2, stats.total_allocs);

    pool_free(pool, ptr1);
    pool_get_stats(pool, &stats);
    ASSERT_EQ(1, stats.used_blocks);
    ASSERT_EQ(1, stats.total_frees);

    pool_free(pool, ptr2);
    pool_destroy(pool);
}

TEST(pool_reuse_freed_blocks) {
    pool_config_t config = {
        .block_size = 64,
        .initial_blocks = 2,
        .max_blocks = 2,
        .zero_on_alloc = false,
        .thread_safe = false
    };

    memory_pool_t *pool = pool_create(&config);

    void *ptr1 = pool_alloc(pool);
    void *ptr2 = pool_alloc(pool);
    ASSERT_NOT_NULL(ptr1);
    ASSERT_NOT_NULL(ptr2);

    /* Pool should be exhausted */
    void *ptr3 = pool_alloc(pool);
    ASSERT_NULL(ptr3);

    /* Free one block */
    pool_free(pool, ptr1);

    /* Should be able to allocate again */
    ptr3 = pool_alloc(pool);
    ASSERT_NOT_NULL(ptr3);

    pool_free(pool, ptr2);
    pool_free(pool, ptr3);
    pool_destroy(pool);
}

TEST(pool_zero_on_alloc) {
    pool_config_t config = {
        .block_size = 64,
        .initial_blocks = 4,
        .max_blocks = 0,
        .zero_on_alloc = true,
        .thread_safe = false
    };

    memory_pool_t *pool = pool_create(&config);

    uint8_t *ptr = pool_alloc(pool);
    ASSERT_NOT_NULL(ptr);

    /* Check that memory is zeroed */
    for (int i = 0; i < 64; i++) {
        ASSERT_EQ(0, ptr[i]);
    }

    pool_free(pool, ptr);
    pool_destroy(pool);
}

TEST(pool_reset) {
    pool_config_t config = {
        .block_size = 64,
        .initial_blocks = 8,
        .max_blocks = 8,
        .zero_on_alloc = false,
        .thread_safe = false
    };

    memory_pool_t *pool = pool_create(&config);

    /* Allocate all blocks */
    for (int i = 0; i < 8; i++) {
        ASSERT_NOT_NULL(pool_alloc(pool));
    }

    pool_stats_t stats;
    pool_get_stats(pool, &stats);
    ASSERT_EQ(8, stats.used_blocks);

    /* Reset pool */
    pool_reset(pool);

    pool_get_stats(pool, &stats);
    ASSERT_EQ(0, stats.used_blocks);
    ASSERT_EQ(8, stats.free_blocks);

    /* Should be able to allocate again */
    ASSERT_NOT_NULL(pool_alloc(pool));

    pool_destroy(pool);
}

TEST(pool_expand) {
    pool_config_t config = {
        .block_size = 64,
        .initial_blocks = 4,
        .max_blocks = 0,  /* Unlimited */
        .zero_on_alloc = false,
        .thread_safe = false
    };

    memory_pool_t *pool = pool_create(&config);

    /* Allocate more than initial */
    void *ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = pool_alloc(pool);
        ASSERT_NOT_NULL(ptrs[i]);
    }

    pool_stats_t stats;
    pool_get_stats(pool, &stats);
    ASSERT_GE(stats.total_blocks, 10);

    for (int i = 0; i < 10; i++) {
        pool_free(pool, ptrs[i]);
    }

    pool_destroy(pool);
}

TEST(pool_manager) {
    ASSERT_EQ(0, pool_manager_init());

    void *ptr1 = pool_manager_alloc(POOL_DECODED_DATA);
    ASSERT_NOT_NULL(ptr1);

    void *ptr2 = pool_manager_alloc(POOL_PAYLOAD_SMALL);
    ASSERT_NOT_NULL(ptr2);

    pool_manager_free(POOL_DECODED_DATA, ptr1);
    pool_manager_free(POOL_PAYLOAD_SMALL, ptr2);

    pool_manager_shutdown();
}

TEST(pool_null_safety) {
    /* Should not crash */
    pool_destroy(NULL);
    pool_free(NULL, NULL);

    pool_stats_t stats;
    pool_get_stats(NULL, &stats);
    pool_reset(NULL);

    ASSERT_NULL(pool_alloc(NULL));
}

/*============================================================================
 * Test Suite Runner
 *============================================================================*/

void run_memory_pool_tests(void) {
    printf("\n" ANSI_BOLD ANSI_CYAN "=== Memory Pool Tests ===" ANSI_RESET "\n");

    RUN_TEST(pool_create_destroy);
    RUN_TEST(pool_create_default);
    RUN_TEST(pool_alloc_free);
    RUN_TEST(pool_stats);
    RUN_TEST(pool_reuse_freed_blocks);
    RUN_TEST(pool_zero_on_alloc);
    RUN_TEST(pool_reset);
    RUN_TEST(pool_expand);
    RUN_TEST(pool_manager);
    RUN_TEST(pool_null_safety);
}
