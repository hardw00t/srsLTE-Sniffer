/**
 * memory_pool.h - Fixed-size block allocator for high-throughput
 *
 * Provides fast, lock-free memory allocation for frequently allocated
 * structures like decoded_data_t and identity records.
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Memory Pool Types
 *============================================================================*/

/**
 * Predefined pool types for common allocations
 */
typedef enum {
    POOL_DECODED_DATA,     /* decoded_data_t structures */
    POOL_PAYLOAD_SMALL,    /* Small payloads (256 bytes) */
    POOL_PAYLOAD_LARGE,    /* Large payloads (1500 bytes) */
    POOL_IDENTITY,         /* Identity records */
    POOL_STRING_SHORT,     /* Short strings (64 bytes) */
    POOL_STRING_LONG,      /* Long strings (256 bytes) */
    POOL_TYPE_COUNT
} pool_type_t;

/*============================================================================
 * Memory Pool Handle
 *============================================================================*/

typedef struct memory_pool memory_pool_t;

/*============================================================================
 * Pool Configuration
 *============================================================================*/

typedef struct {
    size_t   block_size;        /* Size of each block */
    size_t   initial_blocks;    /* Initial number of blocks */
    size_t   max_blocks;        /* Maximum blocks (0 = unlimited) */
    bool     zero_on_alloc;     /* Zero memory on allocation */
    bool     thread_safe;       /* Enable thread safety */
} pool_config_t;

/*============================================================================
 * Pool Statistics
 *============================================================================*/

typedef struct {
    size_t   total_blocks;      /* Total blocks in pool */
    size_t   used_blocks;       /* Currently allocated blocks */
    size_t   free_blocks;       /* Available blocks */
    size_t   peak_usage;        /* Peak block usage */
    uint64_t total_allocs;      /* Total allocations */
    uint64_t total_frees;       /* Total frees */
    uint64_t alloc_failures;    /* Allocation failures */
    size_t   memory_used;       /* Total memory used by pool */
} pool_stats_t;

/*============================================================================
 * Pool Management
 *============================================================================*/

/**
 * Create a new memory pool
 * @param config    Pool configuration
 * @return          Pool handle or NULL on error
 */
memory_pool_t *pool_create(const pool_config_t *config);

/**
 * Create a pool with default configuration for given type
 */
memory_pool_t *pool_create_default(pool_type_t type);

/**
 * Destroy a memory pool and free all memory
 */
void pool_destroy(memory_pool_t *pool);

/**
 * Allocate a block from the pool
 * @param pool      Pool handle
 * @return          Pointer to allocated block or NULL
 */
void *pool_alloc(memory_pool_t *pool);

/**
 * Free a block back to the pool
 * @param pool      Pool handle
 * @param ptr       Block to free
 */
void pool_free(memory_pool_t *pool, void *ptr);

/**
 * Get pool statistics
 */
void pool_get_stats(memory_pool_t *pool, pool_stats_t *stats);

/**
 * Print pool statistics
 */
void pool_print_stats(memory_pool_t *pool, FILE *out);

/**
 * Reset pool (free all allocations)
 */
void pool_reset(memory_pool_t *pool);

/*============================================================================
 * Global Pool Manager
 *============================================================================*/

/**
 * Initialize global pool manager with default pools
 */
int pool_manager_init(void);

/**
 * Shutdown global pool manager
 */
void pool_manager_shutdown(void);

/**
 * Allocate from global pool by type
 */
void *pool_manager_alloc(pool_type_t type);

/**
 * Free to global pool by type
 */
void pool_manager_free(pool_type_t type, void *ptr);

/**
 * Get stats for all pools
 */
void pool_manager_print_stats(FILE *out);

/*============================================================================
 * Convenience Macros
 *============================================================================*/

/**
 * Allocate and zero-initialize a typed structure
 */
#define POOL_ALLOC(pool, type) ((type *)pool_alloc(pool))

/**
 * Allocate from global manager
 */
#define POOL_ALLOC_TYPE(pool_type) pool_manager_alloc(pool_type)

/**
 * Free to global manager
 */
#define POOL_FREE_TYPE(pool_type, ptr) pool_manager_free(pool_type, ptr)

#ifdef __cplusplus
}
#endif

#endif /* MEMORY_POOL_H */
