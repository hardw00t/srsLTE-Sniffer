/**
 * handler_sqlite.h - SQLite database handler for persistent storage
 *
 * Provides persistent storage for captured identities and packets
 * with queryable database.
 *
 * Schema:
 * - captures: All captured packets with metadata
 * - identities: IMSI records with statistics
 * - stmsi_mappings: S-TMSI to IMSI correlations
 * - cells: Cell information from SIBs
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef HANDLER_SQLITE_H
#define HANDLER_SQLITE_H

#include "data_handler.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Database Handle
 *============================================================================*/

typedef struct sqlite_handler sqlite_handler_t;

/*============================================================================
 * Configuration
 *============================================================================*/

typedef struct {
    const char *db_path;        /* Database file path */
    bool        async_writes;   /* Use write-ahead logging */
    bool        compress_blobs; /* Compress payload data */
    uint32_t    cache_size_kb;  /* SQLite cache size */
    bool        create_tables;  /* Auto-create tables if missing */
} sqlite_config_t;

/*============================================================================
 * Database Lifecycle
 *============================================================================*/

/**
 * Create SQLite handler
 * @param config    Configuration (NULL for defaults)
 * @return          Handler or NULL on error
 */
sqlite_handler_t *sqlite_handler_create(const sqlite_config_t *config);

/**
 * Destroy handler and close database
 */
void sqlite_handler_destroy(sqlite_handler_t *handler);

/**
 * Get callback function for data_handler registration
 */
data_handler_callback_t sqlite_get_callback(void);

/**
 * Get handler context for callback registration
 */
void *sqlite_get_context(sqlite_handler_t *handler);

/*============================================================================
 * Direct Insert Functions
 *============================================================================*/

/**
 * Insert capture record
 */
int sqlite_insert_capture(sqlite_handler_t *handler,
                          const decoded_data_t *data);

/**
 * Insert or update identity record
 */
int sqlite_upsert_identity(sqlite_handler_t *handler,
                           const char *imsi,
                           uint16_t cell_id,
                           float rsrp);

/**
 * Insert S-TMSI to IMSI mapping
 */
int sqlite_insert_stmsi_mapping(sqlite_handler_t *handler,
                                 const char *stmsi,
                                 const char *imsi,
                                 uint16_t cell_id);

/**
 * Insert cell information
 */
int sqlite_insert_cell(sqlite_handler_t *handler,
                        uint16_t cell_id,
                        uint16_t tac,
                        uint16_t mcc,
                        uint16_t mnc,
                        const char *sib1_hex,
                        const char *sib2_hex);

/*============================================================================
 * Query Functions
 *============================================================================*/

/**
 * Query result callback
 */
typedef int (*sqlite_result_fn)(void *ctx, int ncols, char **values, char **names);

/**
 * Execute raw SQL query
 */
int sqlite_query(sqlite_handler_t *handler,
                  const char *sql,
                  sqlite_result_fn callback,
                  void *ctx);

/**
 * Get identity count
 */
int sqlite_get_identity_count(sqlite_handler_t *handler);

/**
 * Get capture count
 */
int sqlite_get_capture_count(sqlite_handler_t *handler);

/**
 * Get captures in time range
 */
int sqlite_get_captures_by_time(sqlite_handler_t *handler,
                                 uint64_t start_time,
                                 uint64_t end_time,
                                 sqlite_result_fn callback,
                                 void *ctx);

/**
 * Get all identities for a cell
 */
int sqlite_get_identities_by_cell(sqlite_handler_t *handler,
                                   uint16_t cell_id,
                                   sqlite_result_fn callback,
                                   void *ctx);

/**
 * Look up IMSI from S-TMSI
 */
int sqlite_lookup_imsi(sqlite_handler_t *handler,
                        const char *stmsi,
                        char *imsi_out,
                        size_t imsi_len);

/*============================================================================
 * Maintenance
 *============================================================================*/

/**
 * Optimize database (vacuum, analyze)
 */
int sqlite_optimize(sqlite_handler_t *handler);

/**
 * Delete old captures
 */
int sqlite_prune_captures(sqlite_handler_t *handler, uint64_t older_than);

/**
 * Get database statistics
 */
void sqlite_print_stats(sqlite_handler_t *handler, FILE *out);

/**
 * Begin transaction
 */
int sqlite_begin_transaction(sqlite_handler_t *handler);

/**
 * Commit transaction
 */
int sqlite_commit(sqlite_handler_t *handler);

/**
 * Rollback transaction
 */
int sqlite_rollback(sqlite_handler_t *handler);

#ifdef __cplusplus
}
#endif

#endif /* HANDLER_SQLITE_H */
