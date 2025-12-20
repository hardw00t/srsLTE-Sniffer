/**
 * handler_sqlite.c - SQLite database handler implementation
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifdef ENABLE_SQLITE

#include "handler_sqlite.h"
#include "logger.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/*============================================================================
 * Database Structure
 *============================================================================*/

struct sqlite_handler {
    sqlite3        *db;
    sqlite_config_t config;
    pthread_mutex_t mutex;

    /* Prepared statements */
    sqlite3_stmt   *stmt_insert_capture;
    sqlite3_stmt   *stmt_upsert_identity;
    sqlite3_stmt   *stmt_insert_stmsi;
    sqlite3_stmt   *stmt_insert_cell;

    /* Statistics */
    uint64_t        insert_count;
    uint64_t        query_count;
    uint64_t        error_count;
};

/*============================================================================
 * SQL Statements
 *============================================================================*/

static const char *SQL_CREATE_TABLES =
    "CREATE TABLE IF NOT EXISTS captures ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp INTEGER NOT NULL,"
    "  type TEXT NOT NULL,"
    "  sfn INTEGER,"
    "  sfidx INTEGER,"
    "  rnti INTEGER,"
    "  cell_id INTEGER,"
    "  rsrp REAL,"
    "  snr REAL,"
    "  payload_hex TEXT,"
    "  payload_len INTEGER"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_captures_time ON captures(timestamp);"
    "CREATE INDEX IF NOT EXISTS idx_captures_type ON captures(type);"
    "CREATE INDEX IF NOT EXISTS idx_captures_cell ON captures(cell_id);"

    "CREATE TABLE IF NOT EXISTS identities ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  imsi TEXT UNIQUE NOT NULL,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen INTEGER NOT NULL,"
    "  count INTEGER DEFAULT 1,"
    "  cells_seen TEXT,"
    "  avg_rsrp REAL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_identities_imsi ON identities(imsi);"

    "CREATE TABLE IF NOT EXISTS stmsi_mappings ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  stmsi TEXT NOT NULL,"
    "  imsi TEXT NOT NULL,"
    "  timestamp INTEGER NOT NULL,"
    "  cell_id INTEGER,"
    "  UNIQUE(stmsi, imsi)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_stmsi ON stmsi_mappings(stmsi);"

    "CREATE TABLE IF NOT EXISTS cells ("
    "  cell_id INTEGER PRIMARY KEY,"
    "  tac INTEGER,"
    "  mcc INTEGER,"
    "  mnc INTEGER,"
    "  first_seen INTEGER,"
    "  last_seen INTEGER,"
    "  sib1_hex TEXT,"
    "  sib2_hex TEXT"
    ");";

static const char *SQL_INSERT_CAPTURE =
    "INSERT INTO captures (timestamp, type, sfn, sfidx, rnti, cell_id, rsrp, snr, payload_hex, payload_len) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

static const char *SQL_UPSERT_IDENTITY =
    "INSERT INTO identities (imsi, first_seen, last_seen, count, cells_seen, avg_rsrp) "
    "VALUES (?, ?, ?, 1, ?, ?) "
    "ON CONFLICT(imsi) DO UPDATE SET "
    "last_seen = excluded.last_seen, "
    "count = count + 1, "
    "avg_rsrp = (avg_rsrp * count + excluded.avg_rsrp) / (count + 1)";

static const char *SQL_INSERT_STMSI =
    "INSERT OR IGNORE INTO stmsi_mappings (stmsi, imsi, timestamp, cell_id) "
    "VALUES (?, ?, ?, ?)";

static const char *SQL_INSERT_CELL =
    "INSERT OR REPLACE INTO cells (cell_id, tac, mcc, mnc, first_seen, last_seen, sib1_hex, sib2_hex) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

/*============================================================================
 * Helper Functions
 *============================================================================*/

static int prepare_statements(sqlite_handler_t *handler) {
    int rc;

    rc = sqlite3_prepare_v2(handler->db, SQL_INSERT_CAPTURE, -1,
                            &handler->stmt_insert_capture, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_prepare_v2(handler->db, SQL_UPSERT_IDENTITY, -1,
                            &handler->stmt_upsert_identity, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_prepare_v2(handler->db, SQL_INSERT_STMSI, -1,
                            &handler->stmt_insert_stmsi, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_prepare_v2(handler->db, SQL_INSERT_CELL, -1,
                            &handler->stmt_insert_cell, NULL);
    if (rc != SQLITE_OK) return -1;

    return 0;
}

static void finalize_statements(sqlite_handler_t *handler) {
    if (handler->stmt_insert_capture) {
        sqlite3_finalize(handler->stmt_insert_capture);
    }
    if (handler->stmt_upsert_identity) {
        sqlite3_finalize(handler->stmt_upsert_identity);
    }
    if (handler->stmt_insert_stmsi) {
        sqlite3_finalize(handler->stmt_insert_stmsi);
    }
    if (handler->stmt_insert_cell) {
        sqlite3_finalize(handler->stmt_insert_cell);
    }
}

static void payload_to_hex(const uint8_t *payload, uint32_t len, char *out, size_t max_out) {
    size_t pos = 0;
    for (uint32_t i = 0; i < len && pos + 2 < max_out; i++) {
        pos += snprintf(out + pos, max_out - pos, "%02x", payload[i]);
    }
    out[pos] = '\0';
}

/*============================================================================
 * Database Lifecycle
 *============================================================================*/

sqlite_handler_t *sqlite_handler_create(const sqlite_config_t *config) {
    sqlite_handler_t *handler = calloc(1, sizeof(sqlite_handler_t));
    if (!handler) return NULL;

    /* Apply config */
    if (config) {
        memcpy(&handler->config, config, sizeof(sqlite_config_t));
    } else {
        handler->config.db_path = "captures.db";
        handler->config.async_writes = true;
        handler->config.cache_size_kb = 4096;
        handler->config.create_tables = true;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&handler->mutex, NULL) != 0) {
        free(handler);
        return NULL;
    }

    /* Open database */
    int rc = sqlite3_open(handler->config.db_path, &handler->db);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Cannot open database: %s", sqlite3_errmsg(handler->db));
        pthread_mutex_destroy(&handler->mutex);
        free(handler);
        return NULL;
    }

    /* Configure for performance */
    if (handler->config.async_writes) {
        sqlite3_exec(handler->db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
        sqlite3_exec(handler->db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
    }

    char pragma[64];
    snprintf(pragma, sizeof(pragma), "PRAGMA cache_size=%d",
             handler->config.cache_size_kb);
    sqlite3_exec(handler->db, pragma, NULL, NULL, NULL);

    /* Create tables */
    if (handler->config.create_tables) {
        char *err = NULL;
        rc = sqlite3_exec(handler->db, SQL_CREATE_TABLES, NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            LOG_ERROR("Failed to create tables: %s", err);
            sqlite3_free(err);
            sqlite3_close(handler->db);
            pthread_mutex_destroy(&handler->mutex);
            free(handler);
            return NULL;
        }
    }

    /* Prepare statements */
    if (prepare_statements(handler) != 0) {
        LOG_ERROR("Failed to prepare statements");
        sqlite3_close(handler->db);
        pthread_mutex_destroy(&handler->mutex);
        free(handler);
        return NULL;
    }

    LOG_INFO("SQLite handler initialized: %s", handler->config.db_path);

    return handler;
}

void sqlite_handler_destroy(sqlite_handler_t *handler) {
    if (!handler) return;

    pthread_mutex_lock(&handler->mutex);

    finalize_statements(handler);

    if (handler->db) {
        sqlite3_close(handler->db);
    }

    pthread_mutex_unlock(&handler->mutex);
    pthread_mutex_destroy(&handler->mutex);

    free(handler);
}

/*============================================================================
 * Data Handler Callback
 *============================================================================*/

static void sqlite_callback(const decoded_data_t *data, void *ctx) {
    sqlite_handler_t *handler = (sqlite_handler_t *)ctx;
    sqlite_insert_capture(handler, data);
}

data_handler_callback_t sqlite_get_callback(void) {
    return sqlite_callback;
}

void *sqlite_get_context(sqlite_handler_t *handler) {
    return (void *)handler;
}

/*============================================================================
 * Insert Functions
 *============================================================================*/

int sqlite_insert_capture(sqlite_handler_t *handler, const decoded_data_t *data) {
    if (!handler || !data) return -1;

    pthread_mutex_lock(&handler->mutex);

    sqlite3_stmt *stmt = handler->stmt_insert_capture;
    sqlite3_reset(stmt);

    /* Convert payload to hex */
    char payload_hex[4096];
    payload_to_hex(data->payload, data->payload_len, payload_hex, sizeof(payload_hex));

    /* Get type name */
    const char *type_name = (data->type >= 0 && data->type < DATA_TYPE_COUNT) ?
                            data_type_names[data->type] : "UNKNOWN";

    /* Bind parameters */
    sqlite3_bind_int64(stmt, 1, data->timestamp_us / 1000000);  /* Convert to seconds */
    sqlite3_bind_text(stmt, 2, type_name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, data->sfn);
    sqlite3_bind_int(stmt, 4, data->sfidx);
    sqlite3_bind_int(stmt, 5, data->rnti);
    sqlite3_bind_int(stmt, 6, data->cell_id);
    sqlite3_bind_double(stmt, 7, rsrp_to_dbm(data->rsrp));
    sqlite3_bind_double(stmt, 8, snr_to_db(data->snr));
    sqlite3_bind_text(stmt, 9, payload_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 10, data->payload_len);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        handler->error_count++;
        pthread_mutex_unlock(&handler->mutex);
        return -1;
    }

    handler->insert_count++;
    pthread_mutex_unlock(&handler->mutex);

    return 0;
}

int sqlite_upsert_identity(sqlite_handler_t *handler,
                           const char *imsi,
                           uint16_t cell_id,
                           float rsrp) {
    if (!handler || !imsi) return -1;

    pthread_mutex_lock(&handler->mutex);

    sqlite3_stmt *stmt = handler->stmt_upsert_identity;
    sqlite3_reset(stmt);

    uint64_t now = time(NULL);
    char cells[32];
    snprintf(cells, sizeof(cells), "%u", cell_id);

    sqlite3_bind_text(stmt, 1, imsi, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, now);
    sqlite3_bind_int64(stmt, 3, now);
    sqlite3_bind_text(stmt, 4, cells, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 5, rsrp);

    int rc = sqlite3_step(stmt);
    pthread_mutex_unlock(&handler->mutex);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int sqlite_insert_stmsi_mapping(sqlite_handler_t *handler,
                                 const char *stmsi,
                                 const char *imsi,
                                 uint16_t cell_id) {
    if (!handler || !stmsi || !imsi) return -1;

    pthread_mutex_lock(&handler->mutex);

    sqlite3_stmt *stmt = handler->stmt_insert_stmsi;
    sqlite3_reset(stmt);

    sqlite3_bind_text(stmt, 1, stmsi, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, imsi, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, time(NULL));
    sqlite3_bind_int(stmt, 4, cell_id);

    int rc = sqlite3_step(stmt);
    pthread_mutex_unlock(&handler->mutex);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int sqlite_insert_cell(sqlite_handler_t *handler,
                        uint16_t cell_id,
                        uint16_t tac,
                        uint16_t mcc,
                        uint16_t mnc,
                        const char *sib1_hex,
                        const char *sib2_hex) {
    if (!handler) return -1;

    pthread_mutex_lock(&handler->mutex);

    sqlite3_stmt *stmt = handler->stmt_insert_cell;
    sqlite3_reset(stmt);

    uint64_t now = time(NULL);

    sqlite3_bind_int(stmt, 1, cell_id);
    sqlite3_bind_int(stmt, 2, tac);
    sqlite3_bind_int(stmt, 3, mcc);
    sqlite3_bind_int(stmt, 4, mnc);
    sqlite3_bind_int64(stmt, 5, now);
    sqlite3_bind_int64(stmt, 6, now);
    sqlite3_bind_text(stmt, 7, sib1_hex ? sib1_hex : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, sib2_hex ? sib2_hex : "", -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    pthread_mutex_unlock(&handler->mutex);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/*============================================================================
 * Query Functions
 *============================================================================*/

int sqlite_query(sqlite_handler_t *handler,
                  const char *sql,
                  sqlite_result_fn callback,
                  void *ctx) {
    if (!handler || !sql) return -1;

    pthread_mutex_lock(&handler->mutex);

    char *err = NULL;
    int rc = sqlite3_exec(handler->db, sql, callback, ctx, &err);

    if (rc != SQLITE_OK) {
        LOG_ERROR("Query error: %s", err);
        sqlite3_free(err);
        handler->error_count++;
    } else {
        handler->query_count++;
    }

    pthread_mutex_unlock(&handler->mutex);

    return (rc == SQLITE_OK) ? 0 : -1;
}

int sqlite_get_identity_count(sqlite_handler_t *handler) {
    if (!handler) return -1;

    pthread_mutex_lock(&handler->mutex);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(handler->db, "SELECT COUNT(*) FROM identities",
                                 -1, &stmt, NULL);
    int count = 0;

    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&handler->mutex);

    return count;
}

int sqlite_get_capture_count(sqlite_handler_t *handler) {
    if (!handler) return -1;

    pthread_mutex_lock(&handler->mutex);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(handler->db, "SELECT COUNT(*) FROM captures",
                                 -1, &stmt, NULL);
    int count = 0;

    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&handler->mutex);

    return count;
}

int sqlite_lookup_imsi(sqlite_handler_t *handler,
                        const char *stmsi,
                        char *imsi_out,
                        size_t imsi_len) {
    if (!handler || !stmsi || !imsi_out) return -1;

    pthread_mutex_lock(&handler->mutex);

    const char *sql = "SELECT imsi FROM stmsi_mappings WHERE stmsi = ? "
                      "ORDER BY timestamp DESC LIMIT 1";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(handler->db, sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&handler->mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, stmsi, -1, SQLITE_STATIC);

    int result = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *imsi = (const char *)sqlite3_column_text(stmt, 0);
        strncpy(imsi_out, imsi, imsi_len - 1);
        imsi_out[imsi_len - 1] = '\0';
        result = 0;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&handler->mutex);

    return result;
}

/*============================================================================
 * Maintenance
 *============================================================================*/

int sqlite_optimize(sqlite_handler_t *handler) {
    if (!handler) return -1;

    pthread_mutex_lock(&handler->mutex);

    sqlite3_exec(handler->db, "VACUUM", NULL, NULL, NULL);
    sqlite3_exec(handler->db, "ANALYZE", NULL, NULL, NULL);

    pthread_mutex_unlock(&handler->mutex);

    return 0;
}

int sqlite_prune_captures(sqlite_handler_t *handler, uint64_t older_than) {
    if (!handler) return -1;

    char sql[128];
    snprintf(sql, sizeof(sql),
             "DELETE FROM captures WHERE timestamp < %lu",
             (unsigned long)older_than);

    return sqlite_query(handler, sql, NULL, NULL);
}

void sqlite_print_stats(sqlite_handler_t *handler, FILE *out) {
    if (!handler || !out) return;

    fprintf(out, "\n=== SQLite Handler Statistics ===\n");
    fprintf(out, "Database: %s\n", handler->config.db_path);
    fprintf(out, "Inserts:  %lu\n", (unsigned long)handler->insert_count);
    fprintf(out, "Queries:  %lu\n", (unsigned long)handler->query_count);
    fprintf(out, "Errors:   %lu\n", (unsigned long)handler->error_count);
    fprintf(out, "Identities: %d\n", sqlite_get_identity_count(handler));
    fprintf(out, "Captures:   %d\n", sqlite_get_capture_count(handler));
    fprintf(out, "=================================\n\n");
}

int sqlite_begin_transaction(sqlite_handler_t *handler) {
    if (!handler) return -1;
    return sqlite_query(handler, "BEGIN TRANSACTION", NULL, NULL);
}

int sqlite_commit(sqlite_handler_t *handler) {
    if (!handler) return -1;
    return sqlite_query(handler, "COMMIT", NULL, NULL);
}

int sqlite_rollback(sqlite_handler_t *handler) {
    if (!handler) return -1;
    return sqlite_query(handler, "ROLLBACK", NULL, NULL);
}

#else /* !ENABLE_SQLITE */

/* Stub implementation when SQLite is disabled */
#include "handler_sqlite.h"

sqlite_handler_t *sqlite_handler_create(const sqlite_config_t *config) {
    (void)config;
    return NULL;
}

void sqlite_handler_destroy(sqlite_handler_t *handler) {
    (void)handler;
}

data_handler_callback_t sqlite_get_callback(void) {
    return NULL;
}

void *sqlite_get_context(sqlite_handler_t *handler) {
    (void)handler;
    return NULL;
}

#endif /* ENABLE_SQLITE */
