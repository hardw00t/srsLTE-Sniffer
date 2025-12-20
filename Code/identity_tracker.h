/**
 * identity_tracker.h - GUTI/TMSI/IMSI correlation and tracking
 *
 * Tracks subscriber identities across sessions, correlating
 * S-TMSI assignments to IMSIs and building identity graphs.
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef IDENTITY_TRACKER_H
#define IDENTITY_TRACKER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

#define IMSI_MAX_LEN        16
#define STMSI_MAX_LEN       11
#define GUTI_MAX_LEN        24
#define MAX_CELLS_TRACKED   32
#define MAX_STMSI_HISTORY   32

/*============================================================================
 * Identity Types
 *============================================================================*/

typedef enum {
    IDENTITY_TYPE_IMSI,
    IDENTITY_TYPE_STMSI,
    IDENTITY_TYPE_GUTI,
    IDENTITY_TYPE_UNKNOWN
} identity_type_t;

/*============================================================================
 * Identity Record
 *============================================================================*/

typedef struct {
    /* Primary identity */
    char            imsi[IMSI_MAX_LEN];
    bool            imsi_known;

    /* Current S-TMSI */
    char            stmsi[STMSI_MAX_LEN];
    uint8_t         mmec;                   /* MME Code */
    uint32_t        m_tmsi;                 /* M-TMSI */

    /* GUTI (if known) */
    char            guti[GUTI_MAX_LEN];
    uint16_t        mme_group_id;
    uint16_t        mme_code;

    /* S-TMSI history */
    char            stmsi_history[MAX_STMSI_HISTORY][STMSI_MAX_LEN];
    uint8_t         stmsi_history_count;

    /* Tracking statistics */
    uint64_t        first_seen;             /* Unix timestamp */
    uint64_t        last_seen;              /* Unix timestamp */
    uint32_t        paging_count;           /* Times seen in paging */
    uint32_t        attach_count;           /* Times seen in attach */

    /* Location tracking */
    uint16_t        cells_seen[MAX_CELLS_TRACKED];
    uint8_t         num_cells;
    uint16_t        current_cell;
    uint16_t        current_tac;            /* Tracking Area Code */

    /* Mobility indicators */
    bool            is_stationary;
    float           activity_score;         /* 0-1, higher = more active */

    /* Internal use */
    uint32_t        hash;                   /* For quick lookup */
    bool            dirty;                  /* Needs persistence */
} identity_record_t;

/*============================================================================
 * Tracker Configuration
 *============================================================================*/

typedef struct {
    uint32_t    max_records;            /* Max records in memory */
    uint32_t    expiry_seconds;         /* Remove after inactivity */
    bool        persist_to_db;          /* Use SQLite persistence */
    const char *db_path;                /* Database path */
    bool        track_location;         /* Track cell changes */
    bool        track_mobility;         /* Compute mobility stats */
} tracker_config_t;

/*============================================================================
 * Tracker Statistics
 *============================================================================*/

typedef struct {
    uint32_t    total_records;
    uint32_t    known_imsi_count;
    uint32_t    known_stmsi_count;
    uint32_t    correlated_count;       /* IMSI+S-TMSI pairs */
    uint64_t    total_lookups;
    uint64_t    cache_hits;
    uint64_t    cache_misses;
    uint64_t    expirations;
} tracker_stats_t;

/*============================================================================
 * Tracker Handle
 *============================================================================*/

typedef struct identity_tracker identity_tracker_t;

/*============================================================================
 * Tracker Lifecycle
 *============================================================================*/

/**
 * Create identity tracker
 * @param config    Configuration (NULL for defaults)
 * @return          Tracker handle or NULL
 */
identity_tracker_t *tracker_create(const tracker_config_t *config);

/**
 * Destroy tracker and free resources
 */
void tracker_destroy(identity_tracker_t *tracker);

/*============================================================================
 * Identity Operations
 *============================================================================*/

/**
 * Record an IMSI sighting
 * @param tracker   Tracker handle
 * @param imsi      IMSI string (15 digits)
 * @param cell_id   Cell ID where seen
 * @param tac       Tracking Area Code
 * @return          Pointer to record (valid until next operation)
 */
identity_record_t *tracker_record_imsi(identity_tracker_t *tracker,
                                        const char *imsi,
                                        uint16_t cell_id,
                                        uint16_t tac);

/**
 * Record an S-TMSI sighting
 */
identity_record_t *tracker_record_stmsi(identity_tracker_t *tracker,
                                         const char *stmsi,
                                         uint16_t cell_id,
                                         uint16_t tac);

/**
 * Record IMSI + S-TMSI correlation (seen together in same frame)
 */
identity_record_t *tracker_correlate(identity_tracker_t *tracker,
                                      const char *imsi,
                                      const char *stmsi,
                                      uint16_t cell_id,
                                      uint16_t tac);

/**
 * Update GUTI for an identity
 */
int tracker_update_guti(identity_tracker_t *tracker,
                        const char *imsi_or_stmsi,
                        const char *guti);

/*============================================================================
 * Lookup Operations
 *============================================================================*/

/**
 * Find record by IMSI
 */
identity_record_t *tracker_find_by_imsi(identity_tracker_t *tracker,
                                         const char *imsi);

/**
 * Find record by S-TMSI
 */
identity_record_t *tracker_find_by_stmsi(identity_tracker_t *tracker,
                                          const char *stmsi);

/**
 * Get IMSI from S-TMSI (if correlated)
 * @return IMSI string or NULL if unknown
 */
const char *tracker_stmsi_to_imsi(identity_tracker_t *tracker,
                                   const char *stmsi);

/**
 * Get current S-TMSI for IMSI (if known)
 */
const char *tracker_imsi_to_stmsi(identity_tracker_t *tracker,
                                   const char *imsi);

/*============================================================================
 * Enumeration
 *============================================================================*/

/**
 * Callback for iterating records
 * @return 0 to continue, non-zero to stop
 */
typedef int (*tracker_iterator_fn)(const identity_record_t *record, void *ctx);

/**
 * Iterate all records
 */
void tracker_iterate(identity_tracker_t *tracker,
                     tracker_iterator_fn fn,
                     void *ctx);

/**
 * Iterate records seen in specific cell
 */
void tracker_iterate_by_cell(identity_tracker_t *tracker,
                             uint16_t cell_id,
                             tracker_iterator_fn fn,
                             void *ctx);

/**
 * Get records active in time range
 */
void tracker_iterate_by_time(identity_tracker_t *tracker,
                             uint64_t start_time,
                             uint64_t end_time,
                             tracker_iterator_fn fn,
                             void *ctx);

/*============================================================================
 * Maintenance
 *============================================================================*/

/**
 * Expire old records
 * @return Number of records expired
 */
int tracker_expire_old(identity_tracker_t *tracker);

/**
 * Flush changes to database
 */
int tracker_flush(identity_tracker_t *tracker);

/**
 * Get tracker statistics
 */
void tracker_get_stats(identity_tracker_t *tracker, tracker_stats_t *stats);

/**
 * Print statistics
 */
void tracker_print_stats(identity_tracker_t *tracker, FILE *out);

/**
 * Export to JSON file
 */
int tracker_export_json(identity_tracker_t *tracker, const char *filename);

/*============================================================================
 * Utility Functions
 *============================================================================*/

/**
 * Parse S-TMSI into components
 */
void stmsi_parse(const char *stmsi, uint8_t *mmec, uint32_t *m_tmsi);

/**
 * Format S-TMSI from components
 */
void stmsi_format(uint8_t mmec, uint32_t m_tmsi, char *out);

/**
 * Extract MCC/MNC from IMSI
 */
void imsi_extract_plmn(const char *imsi, uint16_t *mcc, uint16_t *mnc);

/**
 * Get identity type from string
 */
identity_type_t identity_detect_type(const char *identity);

#ifdef __cplusplus
}
#endif

#endif /* IDENTITY_TRACKER_H */
