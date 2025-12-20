/**
 * data_handler.h - Extensible data handler infrastructure for srsLTE-Sniffer
 *
 * Provides callback-based handling of decoded LTE data for:
 * - Real-time processing
 * - Multiple output formats (JSON, database, custom protocols)
 * - Extensibility without modifying core capture code
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef DATA_HANDLER_H
#define DATA_HANDLER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <math.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Types of decoded data that can be handled
 */
typedef enum {
    DATA_TYPE_PAGING = 0,   /* Paging request (contains IMSI/S-TMSI) */
    DATA_TYPE_SIB1,         /* System Information Block Type 1 */
    DATA_TYPE_SIB2,         /* System Information Block Type 2 */
    DATA_TYPE_MIB,          /* Master Information Block */
    DATA_TYPE_OTHER,        /* Other decoded data */
    DATA_TYPE_COUNT         /* Number of data types (for array sizing) */
} data_type_t;

/**
 * String names for data types
 */
static const char *data_type_names[] = {
    "PAGING",
    "SIB1",
    "SIB2",
    "MIB",
    "OTHER"
};

/**
 * Decoded data structure passed to handlers
 */
typedef struct {
    data_type_t type;           /* Type of decoded data */
    uint32_t sfn;               /* System Frame Number (0-1023) */
    uint32_t sfidx;             /* Subframe index (0-9) */
    uint32_t rnti;              /* Radio Network Temporary Identifier */
    uint8_t *payload;           /* Raw payload bytes */
    uint32_t payload_len;       /* Payload length in bytes */
    uint32_t payload_bits;      /* Original payload length in bits */
    float rsrp;                 /* Reference Signal Received Power (linear) */
    float rsrq;                 /* Reference Signal Received Quality (linear) */
    float snr;                  /* Signal-to-Noise Ratio (linear) */
    float cfo;                  /* Carrier Frequency Offset (Hz) */
    uint64_t timestamp_us;      /* Capture timestamp (microseconds since epoch) */
    uint16_t cell_id;           /* Physical Cell ID */
    uint8_t nof_ports;          /* Number of antenna ports */
    uint8_t nof_prb;            /* Number of Physical Resource Blocks */
} decoded_data_t;

/**
 * Callback function type for data handlers
 *
 * @param data    Pointer to decoded data structure
 * @param ctx     User-provided context pointer
 */
typedef void (*data_handler_callback_t)(const decoded_data_t *data, void *ctx);

/**
 * Handler registration entry
 */
typedef struct {
    data_handler_callback_t callback;
    void *context;
    bool enabled;
    const char *name;
} handler_entry_t;

/**
 * Maximum number of handlers that can be registered per data type
 */
#define MAX_HANDLERS_PER_TYPE 8

/**
 * Handler registry (internal - do not access directly)
 */
typedef struct {
    handler_entry_t handlers[DATA_TYPE_COUNT][MAX_HANDLERS_PER_TYPE];
    handler_entry_t global_handlers[MAX_HANDLERS_PER_TYPE]; /* Called for all types */
    bool initialized;
} handler_registry_t;

/*============================================================================
 * API Functions
 *============================================================================*/

/**
 * Initialize the data handler system
 * Must be called before registering handlers
 *
 * @return 0 on success, -1 on error
 */
int data_handler_init(void);

/**
 * Shutdown the data handler system
 * Unregisters all handlers
 */
void data_handler_shutdown(void);

/**
 * Register a callback for a specific data type
 *
 * @param type      Data type to handle
 * @param callback  Callback function
 * @param ctx       User context pointer (passed to callback)
 * @param name      Human-readable handler name (for debugging)
 * @return          Handler ID (>= 0) on success, -1 on error
 */
int data_handler_register(data_type_t type, data_handler_callback_t callback,
                          void *ctx, const char *name);

/**
 * Register a callback for ALL data types
 *
 * @param callback  Callback function
 * @param ctx       User context pointer
 * @param name      Human-readable handler name
 * @return          Handler ID (>= 0) on success, -1 on error
 */
int data_handler_register_global(data_handler_callback_t callback,
                                 void *ctx, const char *name);

/**
 * Unregister a handler by ID
 *
 * @param type       Data type (or -1 for global handler)
 * @param handler_id Handler ID returned from register
 * @return           0 on success, -1 on error
 */
int data_handler_unregister(data_type_t type, int handler_id);

/**
 * Enable or disable a handler
 *
 * @param type       Data type (or -1 for global handler)
 * @param handler_id Handler ID
 * @param enabled    true to enable, false to disable
 * @return           0 on success, -1 on error
 */
int data_handler_set_enabled(data_type_t type, int handler_id, bool enabled);

/**
 * Process decoded data through all registered handlers
 *
 * @param data  Pointer to decoded data structure
 */
void data_handler_process(const decoded_data_t *data);

/**
 * Helper: Fill timestamp in decoded_data_t from current time
 *
 * @param data  Pointer to decoded data structure
 */
static inline void data_handler_set_timestamp(decoded_data_t *data) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    data->timestamp_us = (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

/**
 * Helper: Convert linear RSRP to dBm
 */
static inline float rsrp_to_dbm(float rsrp_linear) {
    return 10.0f * log10f(rsrp_linear) + 30.0f;
}

/**
 * Helper: Convert linear SNR to dB
 */
static inline float snr_to_db(float snr_linear) {
    return 10.0f * log10f(snr_linear);
}

/*============================================================================
 * Built-in Handlers
 *============================================================================*/

/**
 * JSON file output handler
 * Writes JSON Lines (one JSON object per line) to file
 *
 * @param data  Decoded data
 * @param ctx   FILE* pointer to output file
 */
void handler_json_output(const decoded_data_t *data, void *ctx);

/**
 * Console debug handler
 * Prints summary to stderr
 *
 * @param data  Decoded data
 * @param ctx   Unused (can be NULL)
 */
void handler_console_debug(const decoded_data_t *data, void *ctx);

/**
 * Statistics handler
 * Maintains running statistics (call with ctx = stats_context_t*)
 *
 * @param data  Decoded data
 * @param ctx   Pointer to stats_context_t
 */
typedef struct {
    uint64_t total_count;
    uint64_t type_counts[DATA_TYPE_COUNT];
    float avg_snr;
    float avg_rsrp;
    uint64_t start_time_us;
} stats_context_t;

void handler_statistics(const decoded_data_t *data, void *ctx);

/**
 * Print statistics summary
 *
 * @param stats  Statistics context
 * @param out    Output file (e.g., stdout)
 */
void stats_print_summary(const stats_context_t *stats, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* DATA_HANDLER_H */
