/**
 * memory_pool.c - Fixed-size block allocator implementation
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "memory_pool.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>

/*============================================================================
 * Pool Internals
 *============================================================================*/

typedef struct block_node {
    struct block_node *next;
} block_node_t;

struct memory_pool {
    /* Configuration */
    pool_config_t config;

    /* Free list (singly linked) */
    block_node_t *free_list;

    /* Memory chunks (for cleanup) */
    void        **chunks;
    size_t        chunk_count;
    size_t        chunk_capacity;

    /* Statistics */
    pool_stats_t  stats;

    /* Thread safety */
    pthread_mutex_t mutex;
    bool            use_mutex;
};

/* Default configurations for each pool type */
static const pool_config_t default_configs[POOL_TYPE_COUNT] = {
    [POOL_DECODED_DATA] = {
        .block_size = 512,       /* decoded_data_t + some extra */
        .initial_blocks = 256,
        .max_blocks = 4096,
        .zero_on_alloc = true,
        .thread_safe = true
    },
    [POOL_PAYLOAD_SMALL] = {
        .block_size = 256,
        .initial_blocks = 512,
        .max_blocks = 8192,
        .zero_on_alloc = false,
        .thread_safe = true
    },
    [POOL_PAYLOAD_LARGE] = {
        .block_size = 1500,
        .initial_blocks = 128,
        .max_blocks = 2048,
        .zero_on_alloc = false,
        .thread_safe = true
    },
    [POOL_IDENTITY] = {
        .block_size = 256,
        .initial_blocks = 1024,
        .max_blocks = 16384,
        .zero_on_alloc = true,
        .thread_safe = true
    },
    [POOL_STRING_SHORT] = {
        .block_size = 64,
        .initial_blocks = 256,
        .max_blocks = 4096,
        .zero_on_alloc = false,
        .thread_safe = true
    },
    [POOL_STRING_LONG] = {
        .block_size = 256,
        .initial_blocks = 128,
        .max_blocks = 2048,
        .zero_on_alloc = false,
        .thread_safe = true
    }
};

/*============================================================================
 * Helper Functions
 *============================================================================*/

static int allocate_chunk(memory_pool_t *pool) {
    /* Determine chunk size (blocks per chunk) */
    size_t blocks_per_chunk = pool->config.initial_blocks;
    if (pool->stats.total_blocks > 0) {
        blocks_per_chunk = pool->config.initial_blocks / 4;
        if (blocks_per_chunk < 16) blocks_per_chunk = 16;
    }

    /* Check max limit */
    if (pool->config.max_blocks > 0 &&
        pool->stats.total_blocks + blocks_per_chunk > pool->config.max_blocks) {
        blocks_per_chunk = pool->config.max_blocks - pool->stats.total_blocks;
        if (blocks_per_chunk == 0) return -1;
    }

    /* Allocate chunk */
    size_t block_size = pool->config.block_size;
    if (block_size < sizeof(block_node_t)) {
        block_size = sizeof(block_node_t);
    }

    size_t chunk_size = blocks_per_chunk * block_size;
    void *chunk = malloc(chunk_size);
    if (!chunk) return -1;

    /* Initialize all blocks and add to free list */
    for (size_t i = 0; i < blocks_per_chunk; i++) {
        block_node_t *node = (block_node_t *)((char *)chunk + i * block_size);
        node->next = pool->free_list;
        pool->free_list = node;
    }

    /* Track chunk for cleanup */
    if (pool->chunk_count >= pool->chunk_capacity) {
        size_t new_cap = pool->chunk_capacity ? pool->chunk_capacity * 2 : 8;
        void **new_chunks = realloc(pool->chunks, new_cap * sizeof(void *));
        if (!new_chunks) {
            free(chunk);
            return -1;
        }
        pool->chunks = new_chunks;
        pool->chunk_capacity = new_cap;
    }
    pool->chunks[pool->chunk_count++] = chunk;

    /* Update stats */
    pool->stats.total_blocks += blocks_per_chunk;
    pool->stats.free_blocks += blocks_per_chunk;
    pool->stats.memory_used += chunk_size;

    return 0;
}

/*============================================================================
 * Pool Management
 *============================================================================*/

memory_pool_t *pool_create(const pool_config_t *config) {
    if (!config || config->block_size == 0) {
        return NULL;
    }

    memory_pool_t *pool = calloc(1, sizeof(memory_pool_t));
    if (!pool) return NULL;

    memcpy(&pool->config, config, sizeof(pool_config_t));
    pool->use_mutex = config->thread_safe;

    if (pool->use_mutex) {
        if (pthread_mutex_init(&pool->mutex, NULL) != 0) {
            free(pool);
            return NULL;
        }
    }

    /* Allocate initial blocks */
    if (allocate_chunk(pool) != 0) {
        if (pool->use_mutex) {
            pthread_mutex_destroy(&pool->mutex);
        }
        free(pool);
        return NULL;
    }

    return pool;
}

memory_pool_t *pool_create_default(pool_type_t type) {
    if (type < 0 || type >= POOL_TYPE_COUNT) {
        return NULL;
    }
    return pool_create(&default_configs[type]);
}

void pool_destroy(memory_pool_t *pool) {
    if (!pool) return;

    if (pool->use_mutex) {
        pthread_mutex_lock(&pool->mutex);
    }

    /* Free all chunks */
    for (size_t i = 0; i < pool->chunk_count; i++) {
        free(pool->chunks[i]);
    }
    free(pool->chunks);

    if (pool->use_mutex) {
        pthread_mutex_unlock(&pool->mutex);
        pthread_mutex_destroy(&pool->mutex);
    }

    free(pool);
}

void *pool_alloc(memory_pool_t *pool) {
    if (!pool) return NULL;

    if (pool->use_mutex) {
        pthread_mutex_lock(&pool->mutex);
    }

    /* Allocate more if needed */
    if (!pool->free_list) {
        if (allocate_chunk(pool) != 0) {
            pool->stats.alloc_failures++;
            if (pool->use_mutex) {
                pthread_mutex_unlock(&pool->mutex);
            }
            return NULL;
        }
    }

    /* Pop from free list */
    block_node_t *node = pool->free_list;
    pool->free_list = node->next;

    pool->stats.free_blocks--;
    pool->stats.used_blocks++;
    pool->stats.total_allocs++;

    if (pool->stats.used_blocks > pool->stats.peak_usage) {
        pool->stats.peak_usage = pool->stats.used_blocks;
    }

    if (pool->use_mutex) {
        pthread_mutex_unlock(&pool->mutex);
    }

    /* Zero if configured */
    if (pool->config.zero_on_alloc) {
        memset(node, 0, pool->config.block_size);
    }

    return (void *)node;
}

void pool_free(memory_pool_t *pool, void *ptr) {
    if (!pool || !ptr) return;

    if (pool->use_mutex) {
        pthread_mutex_lock(&pool->mutex);
    }

    /* Push to free list */
    block_node_t *node = (block_node_t *)ptr;
    node->next = pool->free_list;
    pool->free_list = node;

    pool->stats.free_blocks++;
    pool->stats.used_blocks--;
    pool->stats.total_frees++;

    if (pool->use_mutex) {
        pthread_mutex_unlock(&pool->mutex);
    }
}

void pool_get_stats(memory_pool_t *pool, pool_stats_t *stats) {
    if (!pool || !stats) return;

    if (pool->use_mutex) {
        pthread_mutex_lock(&pool->mutex);
    }

    memcpy(stats, &pool->stats, sizeof(pool_stats_t));

    if (pool->use_mutex) {
        pthread_mutex_unlock(&pool->mutex);
    }
}

void pool_print_stats(memory_pool_t *pool, FILE *out) {
    if (!pool || !out) return;

    pool_stats_t stats;
    pool_get_stats(pool, &stats);

    fprintf(out, "Pool Statistics:\n");
    fprintf(out, "  Block size:     %zu bytes\n", pool->config.block_size);
    fprintf(out, "  Total blocks:   %zu\n", stats.total_blocks);
    fprintf(out, "  Used blocks:    %zu\n", stats.used_blocks);
    fprintf(out, "  Free blocks:    %zu\n", stats.free_blocks);
    fprintf(out, "  Peak usage:     %zu\n", stats.peak_usage);
    fprintf(out, "  Total allocs:   %lu\n", (unsigned long)stats.total_allocs);
    fprintf(out, "  Total frees:    %lu\n", (unsigned long)stats.total_frees);
    fprintf(out, "  Failures:       %lu\n", (unsigned long)stats.alloc_failures);
    fprintf(out, "  Memory used:    %zu bytes\n", stats.memory_used);
}

void pool_reset(memory_pool_t *pool) {
    if (!pool) return;

    if (pool->use_mutex) {
        pthread_mutex_lock(&pool->mutex);
    }

    /* Rebuild free list from all chunks */
    pool->free_list = NULL;
    pool->stats.used_blocks = 0;
    pool->stats.free_blocks = 0;

    size_t block_size = pool->config.block_size;
    if (block_size < sizeof(block_node_t)) {
        block_size = sizeof(block_node_t);
    }

    size_t blocks_per_chunk = pool->config.initial_blocks;

    for (size_t c = 0; c < pool->chunk_count; c++) {
        for (size_t i = 0; i < blocks_per_chunk; i++) {
            block_node_t *node = (block_node_t *)((char *)pool->chunks[c] + i * block_size);
            node->next = pool->free_list;
            pool->free_list = node;
            pool->stats.free_blocks++;
        }
    }

    if (pool->use_mutex) {
        pthread_mutex_unlock(&pool->mutex);
    }
}

/*============================================================================
 * Global Pool Manager
 *============================================================================*/

static struct {
    memory_pool_t *pools[POOL_TYPE_COUNT];
    bool           initialized;
    pthread_mutex_t mutex;
} g_pool_manager = {0};

int pool_manager_init(void) {
    if (g_pool_manager.initialized) {
        return 0;
    }

    if (pthread_mutex_init(&g_pool_manager.mutex, NULL) != 0) {
        return -1;
    }

    for (int i = 0; i < POOL_TYPE_COUNT; i++) {
        g_pool_manager.pools[i] = pool_create(&default_configs[i]);
        if (!g_pool_manager.pools[i]) {
            /* Cleanup on failure */
            for (int j = 0; j < i; j++) {
                pool_destroy(g_pool_manager.pools[j]);
            }
            pthread_mutex_destroy(&g_pool_manager.mutex);
            return -1;
        }
    }

    g_pool_manager.initialized = true;
    return 0;
}

void pool_manager_shutdown(void) {
    if (!g_pool_manager.initialized) {
        return;
    }

    pthread_mutex_lock(&g_pool_manager.mutex);

    for (int i = 0; i < POOL_TYPE_COUNT; i++) {
        if (g_pool_manager.pools[i]) {
            pool_destroy(g_pool_manager.pools[i]);
            g_pool_manager.pools[i] = NULL;
        }
    }

    g_pool_manager.initialized = false;

    pthread_mutex_unlock(&g_pool_manager.mutex);
    pthread_mutex_destroy(&g_pool_manager.mutex);
}

void *pool_manager_alloc(pool_type_t type) {
    if (!g_pool_manager.initialized || type < 0 || type >= POOL_TYPE_COUNT) {
        return NULL;
    }
    return pool_alloc(g_pool_manager.pools[type]);
}

void pool_manager_free(pool_type_t type, void *ptr) {
    if (!g_pool_manager.initialized || type < 0 || type >= POOL_TYPE_COUNT) {
        return;
    }
    pool_free(g_pool_manager.pools[type], ptr);
}

void pool_manager_print_stats(FILE *out) {
    if (!g_pool_manager.initialized || !out) return;

    static const char *type_names[] = {
        "DECODED_DATA", "PAYLOAD_SMALL", "PAYLOAD_LARGE",
        "IDENTITY", "STRING_SHORT", "STRING_LONG"
    };

    fprintf(out, "\n=== Pool Manager Statistics ===\n");

    for (int i = 0; i < POOL_TYPE_COUNT; i++) {
        if (g_pool_manager.pools[i]) {
            fprintf(out, "\n[%s]\n", type_names[i]);
            pool_print_stats(g_pool_manager.pools[i], out);
        }
    }

    fprintf(out, "================================\n");
}
