/**
 * data_handler.c - Implementation of extensible data handler infrastructure
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "data_handler.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* Global handler registry */
static handler_registry_t registry = {0};

/*============================================================================
 * Core API Implementation
 *============================================================================*/

int data_handler_init(void) {
    if (registry.initialized) {
        return 0; /* Already initialized */
    }

    memset(&registry, 0, sizeof(registry));
    registry.initialized = true;
    return 0;
}

void data_handler_shutdown(void) {
    if (!registry.initialized) {
        return;
    }

    /* Clear all handlers */
    memset(&registry, 0, sizeof(registry));
}

int data_handler_register(data_type_t type, data_handler_callback_t callback,
                          void *ctx, const char *name) {
    if (!registry.initialized) {
        data_handler_init();
    }

    if (type < 0 || type >= DATA_TYPE_COUNT || callback == NULL) {
        return -1;
    }

    /* Find empty slot */
    for (int i = 0; i < MAX_HANDLERS_PER_TYPE; i++) {
        if (registry.handlers[type][i].callback == NULL) {
            registry.handlers[type][i].callback = callback;
            registry.handlers[type][i].context = ctx;
            registry.handlers[type][i].enabled = true;
            registry.handlers[type][i].name = name;
            return i;
        }
    }

    return -1; /* No empty slots */
}

int data_handler_register_global(data_handler_callback_t callback,
                                 void *ctx, const char *name) {
    if (!registry.initialized) {
        data_handler_init();
    }

    if (callback == NULL) {
        return -1;
    }

    /* Find empty slot in global handlers */
    for (int i = 0; i < MAX_HANDLERS_PER_TYPE; i++) {
        if (registry.global_handlers[i].callback == NULL) {
            registry.global_handlers[i].callback = callback;
            registry.global_handlers[i].context = ctx;
            registry.global_handlers[i].enabled = true;
            registry.global_handlers[i].name = name;
            return i;
        }
    }

    return -1; /* No empty slots */
}

int data_handler_unregister(data_type_t type, int handler_id) {
    if (!registry.initialized) {
        return -1;
    }

    if (handler_id < 0 || handler_id >= MAX_HANDLERS_PER_TYPE) {
        return -1;
    }

    handler_entry_t *entry;
    if (type < 0) {
        /* Global handler */
        entry = &registry.global_handlers[handler_id];
    } else if (type < DATA_TYPE_COUNT) {
        entry = &registry.handlers[type][handler_id];
    } else {
        return -1;
    }

    memset(entry, 0, sizeof(handler_entry_t));
    return 0;
}

int data_handler_set_enabled(data_type_t type, int handler_id, bool enabled) {
    if (!registry.initialized) {
        return -1;
    }

    if (handler_id < 0 || handler_id >= MAX_HANDLERS_PER_TYPE) {
        return -1;
    }

    handler_entry_t *entry;
    if (type < 0) {
        entry = &registry.global_handlers[handler_id];
    } else if (type < DATA_TYPE_COUNT) {
        entry = &registry.handlers[type][handler_id];
    } else {
        return -1;
    }

    if (entry->callback == NULL) {
        return -1; /* No handler registered */
    }

    entry->enabled = enabled;
    return 0;
}

void data_handler_process(const decoded_data_t *data) {
    if (!registry.initialized || data == NULL) {
        return;
    }

    /* Call type-specific handlers */
    if (data->type >= 0 && data->type < DATA_TYPE_COUNT) {
        for (int i = 0; i < MAX_HANDLERS_PER_TYPE; i++) {
            handler_entry_t *entry = &registry.handlers[data->type][i];
            if (entry->callback != NULL && entry->enabled) {
                entry->callback(data, entry->context);
            }
        }
    }

    /* Call global handlers */
    for (int i = 0; i < MAX_HANDLERS_PER_TYPE; i++) {
        handler_entry_t *entry = &registry.global_handlers[i];
        if (entry->callback != NULL && entry->enabled) {
            entry->callback(data, entry->context);
        }
    }
}

/*============================================================================
 * Built-in Handler Implementations
 *============================================================================*/

void handler_json_output(const decoded_data_t *data, void *ctx) {
    FILE *out = (FILE *)ctx;
    if (out == NULL || data == NULL) {
        return;
    }

    /* Write JSON object */
    fprintf(out, "{\"type\":\"%s\"",
            (data->type >= 0 && data->type < DATA_TYPE_COUNT) ?
            data_type_names[data->type] : "UNKNOWN");

    fprintf(out, ",\"timestamp\":%lu", (unsigned long)data->timestamp_us);
    fprintf(out, ",\"sfn\":%u", data->sfn);
    fprintf(out, ",\"sfidx\":%u", data->sfidx);
    fprintf(out, ",\"rnti\":%u", data->rnti);
    fprintf(out, ",\"cell_id\":%u", data->cell_id);

    /* Signal metrics (convert to dB/dBm for readability) */
    if (data->rsrp > 0) {
        fprintf(out, ",\"rsrp_dbm\":%.1f", rsrp_to_dbm(data->rsrp));
    }
    if (data->snr > 0) {
        fprintf(out, ",\"snr_db\":%.1f", snr_to_db(data->snr));
    }
    if (data->cfo != 0) {
        fprintf(out, ",\"cfo_hz\":%.1f", data->cfo);
    }

    /* Payload as hex string */
    fprintf(out, ",\"payload_len\":%u", data->payload_len);
    fprintf(out, ",\"payload\":\"");
    for (uint32_t i = 0; i < data->payload_len && i < 256; i++) {
        fprintf(out, "%02x", data->payload[i]);
    }
    if (data->payload_len > 256) {
        fprintf(out, "...");
    }
    fprintf(out, "\"");

    fprintf(out, "}\n");
    fflush(out);
}

void handler_console_debug(const decoded_data_t *data, void *ctx) {
    (void)ctx; /* Unused */

    if (data == NULL) {
        return;
    }

    const char *type_str = (data->type >= 0 && data->type < DATA_TYPE_COUNT) ?
                           data_type_names[data->type] : "UNKNOWN";

    fprintf(stderr, "[%s] SFN=%u.%u RNTI=0x%04x len=%u",
            type_str, data->sfn, data->sfidx, data->rnti, data->payload_len);

    if (data->snr > 0) {
        fprintf(stderr, " SNR=%.1fdB", snr_to_db(data->snr));
    }

    /* Print first few bytes of payload */
    if (data->payload_len > 0) {
        fprintf(stderr, " payload=");
        for (uint32_t i = 0; i < data->payload_len && i < 8; i++) {
            fprintf(stderr, "%02x", data->payload[i]);
        }
        if (data->payload_len > 8) {
            fprintf(stderr, "...");
        }
    }

    fprintf(stderr, "\n");
}

void handler_statistics(const decoded_data_t *data, void *ctx) {
    stats_context_t *stats = (stats_context_t *)ctx;
    if (stats == NULL || data == NULL) {
        return;
    }

    /* Initialize start time on first call */
    if (stats->start_time_us == 0) {
        stats->start_time_us = data->timestamp_us;
    }

    stats->total_count++;

    if (data->type >= 0 && data->type < DATA_TYPE_COUNT) {
        stats->type_counts[data->type]++;
    }

    /* Running average of signal metrics */
    if (data->snr > 0) {
        float alpha = 0.1f; /* Exponential moving average coefficient */
        if (stats->avg_snr == 0) {
            stats->avg_snr = snr_to_db(data->snr);
        } else {
            stats->avg_snr = stats->avg_snr * (1.0f - alpha) +
                             snr_to_db(data->snr) * alpha;
        }
    }

    if (data->rsrp > 0) {
        float alpha = 0.1f;
        if (stats->avg_rsrp == 0) {
            stats->avg_rsrp = rsrp_to_dbm(data->rsrp);
        } else {
            stats->avg_rsrp = stats->avg_rsrp * (1.0f - alpha) +
                              rsrp_to_dbm(data->rsrp) * alpha;
        }
    }
}

void stats_print_summary(const stats_context_t *stats, FILE *out) {
    if (stats == NULL || out == NULL) {
        return;
    }

    fprintf(out, "\n=== Capture Statistics ===\n");
    fprintf(out, "Total packets: %lu\n", (unsigned long)stats->total_count);

    fprintf(out, "\nPackets by type:\n");
    for (int i = 0; i < DATA_TYPE_COUNT; i++) {
        if (stats->type_counts[i] > 0) {
            fprintf(out, "  %-10s: %lu\n", data_type_names[i],
                    (unsigned long)stats->type_counts[i]);
        }
    }

    fprintf(out, "\nSignal quality:\n");
    fprintf(out, "  Avg SNR:  %.1f dB\n", stats->avg_snr);
    fprintf(out, "  Avg RSRP: %.1f dBm\n", stats->avg_rsrp);

    if (stats->start_time_us > 0 && stats->total_count > 0) {
        /* Estimate capture duration and rate */
        /* Note: This is approximate since we don't track end time here */
        fprintf(out, "\n");
    }

    fprintf(out, "===========================\n\n");
}
