/**
 * identity_tracker.c - GUTI/TMSI/IMSI correlation implementation
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "identity_tracker.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <ctype.h>

/*============================================================================
 * Hash Table Implementation
 *============================================================================*/

#define HASH_SIZE 4096

typedef struct hash_entry {
    identity_record_t   record;
    struct hash_entry  *next;
    bool                used;
} hash_entry_t;

struct identity_tracker {
    tracker_config_t    config;

    /* Primary hash by IMSI */
    hash_entry_t       *imsi_table[HASH_SIZE];

    /* Secondary index by S-TMSI */
    hash_entry_t       *stmsi_table[HASH_SIZE];

    /* Statistics */
    tracker_stats_t     stats;

    /* Thread safety */
    pthread_mutex_t     mutex;
};

/*============================================================================
 * Hash Function
 *============================================================================*/

static uint32_t djb2_hash(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

static uint32_t hash_index(const char *str) {
    return djb2_hash(str) % HASH_SIZE;
}

/*============================================================================
 * Tracker Lifecycle
 *============================================================================*/

static void config_defaults(tracker_config_t *config) {
    config->max_records = 10000;
    config->expiry_seconds = 86400;  /* 24 hours */
    config->persist_to_db = false;
    config->db_path = NULL;
    config->track_location = true;
    config->track_mobility = true;
}

identity_tracker_t *tracker_create(const tracker_config_t *config) {
    identity_tracker_t *tracker = calloc(1, sizeof(identity_tracker_t));
    if (!tracker) return NULL;

    if (config) {
        memcpy(&tracker->config, config, sizeof(tracker_config_t));
    } else {
        config_defaults(&tracker->config);
    }

    if (pthread_mutex_init(&tracker->mutex, NULL) != 0) {
        free(tracker);
        return NULL;
    }

    return tracker;
}

void tracker_destroy(identity_tracker_t *tracker) {
    if (!tracker) return;

    pthread_mutex_lock(&tracker->mutex);

    /* Free all entries */
    for (int i = 0; i < HASH_SIZE; i++) {
        hash_entry_t *entry = tracker->imsi_table[i];
        while (entry) {
            hash_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    pthread_mutex_unlock(&tracker->mutex);
    pthread_mutex_destroy(&tracker->mutex);

    free(tracker);
}

/*============================================================================
 * Internal Helpers
 *============================================================================*/

static hash_entry_t *find_by_imsi_internal(identity_tracker_t *tracker, const char *imsi) {
    uint32_t idx = hash_index(imsi);
    hash_entry_t *entry = tracker->imsi_table[idx];

    while (entry) {
        if (entry->used && strcmp(entry->record.imsi, imsi) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

static hash_entry_t *find_by_stmsi_internal(identity_tracker_t *tracker, const char *stmsi) {
    uint32_t idx = hash_index(stmsi);
    hash_entry_t *entry = tracker->stmsi_table[idx];

    while (entry) {
        if (entry->used && strcmp(entry->record.stmsi, stmsi) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

static void add_to_stmsi_index(identity_tracker_t *tracker, hash_entry_t *entry) {
    if (entry->record.stmsi[0] == '\0') return;

    uint32_t idx = hash_index(entry->record.stmsi);
    entry->next = tracker->stmsi_table[idx];
    tracker->stmsi_table[idx] = entry;
}

static void update_cell_list(identity_record_t *record, uint16_t cell_id) {
    /* Check if already tracked */
    for (int i = 0; i < record->num_cells; i++) {
        if (record->cells_seen[i] == cell_id) {
            return;
        }
    }

    /* Add to list */
    if (record->num_cells < MAX_CELLS_TRACKED) {
        record->cells_seen[record->num_cells++] = cell_id;
    }
}

static void update_stmsi_history(identity_record_t *record, const char *stmsi) {
    /* Don't add if already current */
    if (strcmp(record->stmsi, stmsi) == 0) return;

    /* Shift history */
    if (record->stmsi_history_count < MAX_STMSI_HISTORY) {
        record->stmsi_history_count++;
    }
    for (int i = record->stmsi_history_count - 1; i > 0; i--) {
        strncpy(record->stmsi_history[i], record->stmsi_history[i-1], STMSI_MAX_LEN);
    }

    /* Add old S-TMSI to history */
    if (record->stmsi[0] != '\0') {
        strncpy(record->stmsi_history[0], record->stmsi, STMSI_MAX_LEN);
    }

    /* Update current */
    strncpy(record->stmsi, stmsi, STMSI_MAX_LEN - 1);
    record->stmsi[STMSI_MAX_LEN - 1] = '\0';
}

/*============================================================================
 * Identity Operations
 *============================================================================*/

identity_record_t *tracker_record_imsi(identity_tracker_t *tracker,
                                        const char *imsi,
                                        uint16_t cell_id,
                                        uint16_t tac) {
    if (!tracker || !imsi || strlen(imsi) == 0) return NULL;

    pthread_mutex_lock(&tracker->mutex);
    tracker->stats.total_lookups++;

    hash_entry_t *entry = find_by_imsi_internal(tracker, imsi);

    if (entry) {
        tracker->stats.cache_hits++;
    } else {
        tracker->stats.cache_misses++;

        /* Create new entry */
        entry = calloc(1, sizeof(hash_entry_t));
        if (!entry) {
            pthread_mutex_unlock(&tracker->mutex);
            return NULL;
        }

        strncpy(entry->record.imsi, imsi, IMSI_MAX_LEN - 1);
        entry->record.imsi_known = true;
        entry->record.first_seen = time(NULL);
        entry->record.hash = djb2_hash(imsi);
        entry->used = true;

        /* Add to hash table */
        uint32_t idx = hash_index(imsi);
        entry->next = tracker->imsi_table[idx];
        tracker->imsi_table[idx] = entry;

        tracker->stats.total_records++;
        tracker->stats.known_imsi_count++;
    }

    /* Update record */
    entry->record.last_seen = time(NULL);
    entry->record.paging_count++;
    entry->record.current_cell = cell_id;
    entry->record.current_tac = tac;
    entry->record.dirty = true;

    if (tracker->config.track_location) {
        update_cell_list(&entry->record, cell_id);
    }

    pthread_mutex_unlock(&tracker->mutex);

    return &entry->record;
}

identity_record_t *tracker_record_stmsi(identity_tracker_t *tracker,
                                         const char *stmsi,
                                         uint16_t cell_id,
                                         uint16_t tac) {
    if (!tracker || !stmsi || strlen(stmsi) == 0) return NULL;

    pthread_mutex_lock(&tracker->mutex);
    tracker->stats.total_lookups++;

    hash_entry_t *entry = find_by_stmsi_internal(tracker, stmsi);

    if (entry) {
        tracker->stats.cache_hits++;
    } else {
        tracker->stats.cache_misses++;

        /* Create new entry (S-TMSI only, no IMSI yet) */
        entry = calloc(1, sizeof(hash_entry_t));
        if (!entry) {
            pthread_mutex_unlock(&tracker->mutex);
            return NULL;
        }

        strncpy(entry->record.stmsi, stmsi, STMSI_MAX_LEN - 1);
        entry->record.first_seen = time(NULL);
        entry->used = true;

        /* Add to S-TMSI index */
        uint32_t idx = hash_index(stmsi);
        entry->next = tracker->stmsi_table[idx];
        tracker->stmsi_table[idx] = entry;

        tracker->stats.total_records++;
        tracker->stats.known_stmsi_count++;
    }

    /* Update record */
    entry->record.last_seen = time(NULL);
    entry->record.paging_count++;
    entry->record.current_cell = cell_id;
    entry->record.current_tac = tac;
    entry->record.dirty = true;

    if (tracker->config.track_location) {
        update_cell_list(&entry->record, cell_id);
    }

    pthread_mutex_unlock(&tracker->mutex);

    return &entry->record;
}

identity_record_t *tracker_correlate(identity_tracker_t *tracker,
                                      const char *imsi,
                                      const char *stmsi,
                                      uint16_t cell_id,
                                      uint16_t tac) {
    if (!tracker || !imsi || !stmsi) return NULL;

    pthread_mutex_lock(&tracker->mutex);
    tracker->stats.total_lookups++;

    /* Find or create IMSI record */
    hash_entry_t *entry = find_by_imsi_internal(tracker, imsi);

    if (!entry) {
        entry = calloc(1, sizeof(hash_entry_t));
        if (!entry) {
            pthread_mutex_unlock(&tracker->mutex);
            return NULL;
        }

        strncpy(entry->record.imsi, imsi, IMSI_MAX_LEN - 1);
        entry->record.imsi_known = true;
        entry->record.first_seen = time(NULL);
        entry->record.hash = djb2_hash(imsi);
        entry->used = true;

        uint32_t idx = hash_index(imsi);
        entry->next = tracker->imsi_table[idx];
        tracker->imsi_table[idx] = entry;

        tracker->stats.total_records++;
        tracker->stats.known_imsi_count++;
    }

    /* Update S-TMSI correlation */
    bool new_correlation = (entry->record.stmsi[0] == '\0');
    update_stmsi_history(&entry->record, stmsi);

    if (new_correlation) {
        add_to_stmsi_index(tracker, entry);
        tracker->stats.correlated_count++;
    }

    /* Update record */
    entry->record.last_seen = time(NULL);
    entry->record.paging_count++;
    entry->record.current_cell = cell_id;
    entry->record.current_tac = tac;
    entry->record.dirty = true;

    if (tracker->config.track_location) {
        update_cell_list(&entry->record, cell_id);
    }

    pthread_mutex_unlock(&tracker->mutex);

    return &entry->record;
}

/*============================================================================
 * Lookup Operations
 *============================================================================*/

identity_record_t *tracker_find_by_imsi(identity_tracker_t *tracker,
                                         const char *imsi) {
    if (!tracker || !imsi) return NULL;

    pthread_mutex_lock(&tracker->mutex);
    hash_entry_t *entry = find_by_imsi_internal(tracker, imsi);
    pthread_mutex_unlock(&tracker->mutex);

    return entry ? &entry->record : NULL;
}

identity_record_t *tracker_find_by_stmsi(identity_tracker_t *tracker,
                                          const char *stmsi) {
    if (!tracker || !stmsi) return NULL;

    pthread_mutex_lock(&tracker->mutex);
    hash_entry_t *entry = find_by_stmsi_internal(tracker, stmsi);
    pthread_mutex_unlock(&tracker->mutex);

    return entry ? &entry->record : NULL;
}

const char *tracker_stmsi_to_imsi(identity_tracker_t *tracker,
                                   const char *stmsi) {
    identity_record_t *rec = tracker_find_by_stmsi(tracker, stmsi);
    return (rec && rec->imsi_known) ? rec->imsi : NULL;
}

const char *tracker_imsi_to_stmsi(identity_tracker_t *tracker,
                                   const char *imsi) {
    identity_record_t *rec = tracker_find_by_imsi(tracker, imsi);
    return (rec && rec->stmsi[0]) ? rec->stmsi : NULL;
}

/*============================================================================
 * Enumeration
 *============================================================================*/

void tracker_iterate(identity_tracker_t *tracker,
                     tracker_iterator_fn fn,
                     void *ctx) {
    if (!tracker || !fn) return;

    pthread_mutex_lock(&tracker->mutex);

    for (int i = 0; i < HASH_SIZE; i++) {
        hash_entry_t *entry = tracker->imsi_table[i];
        while (entry) {
            if (entry->used) {
                if (fn(&entry->record, ctx) != 0) {
                    pthread_mutex_unlock(&tracker->mutex);
                    return;
                }
            }
            entry = entry->next;
        }
    }

    pthread_mutex_unlock(&tracker->mutex);
}

void tracker_iterate_by_cell(identity_tracker_t *tracker,
                             uint16_t cell_id,
                             tracker_iterator_fn fn,
                             void *ctx) {
    if (!tracker || !fn) return;

    pthread_mutex_lock(&tracker->mutex);

    for (int i = 0; i < HASH_SIZE; i++) {
        hash_entry_t *entry = tracker->imsi_table[i];
        while (entry) {
            if (entry->used) {
                for (int j = 0; j < entry->record.num_cells; j++) {
                    if (entry->record.cells_seen[j] == cell_id) {
                        if (fn(&entry->record, ctx) != 0) {
                            pthread_mutex_unlock(&tracker->mutex);
                            return;
                        }
                        break;
                    }
                }
            }
            entry = entry->next;
        }
    }

    pthread_mutex_unlock(&tracker->mutex);
}

/*============================================================================
 * Maintenance
 *============================================================================*/

int tracker_expire_old(identity_tracker_t *tracker) {
    if (!tracker) return 0;

    pthread_mutex_lock(&tracker->mutex);

    uint64_t now = time(NULL);
    uint64_t cutoff = now - tracker->config.expiry_seconds;
    int expired = 0;

    for (int i = 0; i < HASH_SIZE; i++) {
        hash_entry_t **ptr = &tracker->imsi_table[i];
        while (*ptr) {
            hash_entry_t *entry = *ptr;
            if (entry->used && entry->record.last_seen < cutoff) {
                *ptr = entry->next;
                free(entry);
                expired++;
                tracker->stats.total_records--;
            } else {
                ptr = &entry->next;
            }
        }
    }

    tracker->stats.expirations += expired;

    pthread_mutex_unlock(&tracker->mutex);

    return expired;
}

void tracker_get_stats(identity_tracker_t *tracker, tracker_stats_t *stats) {
    if (!tracker || !stats) return;

    pthread_mutex_lock(&tracker->mutex);
    memcpy(stats, &tracker->stats, sizeof(tracker_stats_t));
    pthread_mutex_unlock(&tracker->mutex);
}

void tracker_print_stats(identity_tracker_t *tracker, FILE *out) {
    if (!tracker || !out) return;

    tracker_stats_t stats;
    tracker_get_stats(tracker, &stats);

    fprintf(out, "\n=== Identity Tracker Statistics ===\n");
    fprintf(out, "Total records:    %u\n", stats.total_records);
    fprintf(out, "Known IMSIs:      %u\n", stats.known_imsi_count);
    fprintf(out, "Known S-TMSIs:    %u\n", stats.known_stmsi_count);
    fprintf(out, "Correlated pairs: %u\n", stats.correlated_count);
    fprintf(out, "Total lookups:    %lu\n", (unsigned long)stats.total_lookups);
    fprintf(out, "Cache hits:       %lu (%.1f%%)\n",
            (unsigned long)stats.cache_hits,
            stats.total_lookups > 0 ? 100.0 * stats.cache_hits / stats.total_lookups : 0);
    fprintf(out, "Expirations:      %lu\n", (unsigned long)stats.expirations);
    fprintf(out, "===================================\n\n");
}

int tracker_export_json(identity_tracker_t *tracker, const char *filename) {
    if (!tracker || !filename) return -1;

    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    pthread_mutex_lock(&tracker->mutex);

    fprintf(fp, "[\n");
    bool first = true;

    for (int i = 0; i < HASH_SIZE; i++) {
        hash_entry_t *entry = tracker->imsi_table[i];
        while (entry) {
            if (entry->used) {
                if (!first) fprintf(fp, ",\n");
                first = false;

                identity_record_t *r = &entry->record;
                fprintf(fp, "  {\"imsi\": \"%s\", \"stmsi\": \"%s\", ",
                        r->imsi, r->stmsi);
                fprintf(fp, "\"first_seen\": %lu, \"last_seen\": %lu, ",
                        (unsigned long)r->first_seen, (unsigned long)r->last_seen);
                fprintf(fp, "\"paging_count\": %u, \"cells\": [",
                        r->paging_count);

                for (int j = 0; j < r->num_cells; j++) {
                    fprintf(fp, "%u%s", r->cells_seen[j],
                            j + 1 < r->num_cells ? ", " : "");
                }
                fprintf(fp, "]}");
            }
            entry = entry->next;
        }
    }

    fprintf(fp, "\n]\n");

    pthread_mutex_unlock(&tracker->mutex);

    fclose(fp);
    return 0;
}

/*============================================================================
 * Utility Functions
 *============================================================================*/

void stmsi_parse(const char *stmsi, uint8_t *mmec, uint32_t *m_tmsi) {
    if (!stmsi || strlen(stmsi) < 10) return;

    /* S-TMSI format: MMEC (2 hex) + M-TMSI (8 hex) */
    char mmec_str[3] = {stmsi[0], stmsi[1], '\0'};
    *mmec = (uint8_t)strtoul(mmec_str, NULL, 16);
    *m_tmsi = (uint32_t)strtoul(stmsi + 2, NULL, 16);
}

void stmsi_format(uint8_t mmec, uint32_t m_tmsi, char *out) {
    snprintf(out, STMSI_MAX_LEN, "%02x%08x", mmec, m_tmsi);
}

void imsi_extract_plmn(const char *imsi, uint16_t *mcc, uint16_t *mnc) {
    if (!imsi || strlen(imsi) < 6) return;

    char mcc_str[4] = {imsi[0], imsi[1], imsi[2], '\0'};
    *mcc = (uint16_t)atoi(mcc_str);

    /* MNC can be 2 or 3 digits */
    char mnc_str[4] = {imsi[3], imsi[4], '\0', '\0'};
    if (isdigit(imsi[5]) && strlen(imsi) >= 6) {
        mnc_str[2] = imsi[5];
    }
    *mnc = (uint16_t)atoi(mnc_str);
}

identity_type_t identity_detect_type(const char *identity) {
    if (!identity) return IDENTITY_TYPE_UNKNOWN;

    size_t len = strlen(identity);

    /* IMSI: 15 decimal digits */
    if (len == 15) {
        bool all_digits = true;
        for (size_t i = 0; i < len; i++) {
            if (!isdigit(identity[i])) {
                all_digits = false;
                break;
            }
        }
        if (all_digits) return IDENTITY_TYPE_IMSI;
    }

    /* S-TMSI: 10 hex characters */
    if (len == 10) {
        bool all_hex = true;
        for (size_t i = 0; i < len; i++) {
            if (!isxdigit(identity[i])) {
                all_hex = false;
                break;
            }
        }
        if (all_hex) return IDENTITY_TYPE_STMSI;
    }

    /* GUTI: longer format */
    if (len > 15) {
        return IDENTITY_TYPE_GUTI;
    }

    return IDENTITY_TYPE_UNKNOWN;
}
