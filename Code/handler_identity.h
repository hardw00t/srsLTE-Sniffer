/**
 * handler_identity.h - Identity extraction handler for paging messages
 *
 * Automatically extracts IMSI and S-TMSI from paging messages
 * and routes them to the identity tracker for correlation.
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef HANDLER_IDENTITY_H
#define HANDLER_IDENTITY_H

#include "data_handler.h"
#include "identity_tracker.h"
#include "paging_parser.h"
#include "mib_parser.h"
#include "sib_parser.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Configuration
 *============================================================================*/

typedef struct {
    /* Enable/disable features */
    bool extract_imsi;          /* Extract IMSI from paging */
    bool extract_stmsi;         /* Extract S-TMSI from paging */
    bool correlate_identities;  /* Try to correlate IMSI+S-TMSI */
    bool track_cells;           /* Track cells where identities are seen */

    /* Parsing options */
    bool use_heuristic;         /* Use heuristic parsing if ASN.1 fails */

    /* Output options */
    bool log_to_file;           /* Write extracted identities to file */
    FILE *log_file;             /* Output file handle */
    bool log_json;              /* Use JSON format for logging */

    /* Statistics */
    bool collect_stats;         /* Collect extraction statistics */
} identity_handler_config_t;

/*============================================================================
 * Statistics
 *============================================================================*/

typedef struct {
    uint64_t paging_messages;       /* Total paging messages processed */
    uint64_t imsi_extracted;        /* Number of IMSIs extracted */
    uint64_t stmsi_extracted;       /* Number of S-TMSIs extracted */
    uint64_t correlations;          /* IMSI+S-TMSI correlations made */
    uint64_t parse_failures;        /* ASN.1 parse failures */
    uint64_t heuristic_success;     /* Heuristic extraction successes */
    uint64_t unique_imsi;           /* Unique IMSIs seen */
    uint64_t unique_stmsi;          /* Unique S-TMSIs seen */
} identity_handler_stats_t;

/*============================================================================
 * Handler Context
 *============================================================================*/

typedef struct {
    identity_handler_config_t config;
    identity_tracker_t *tracker;
    identity_handler_stats_t stats;
    bool owns_tracker;              /* true if we created the tracker */
} identity_handler_ctx_t;

/*============================================================================
 * API Functions
 *============================================================================*/

/**
 * Create identity handler context with default configuration
 *
 * @return  New context, or NULL on error
 */
identity_handler_ctx_t *identity_handler_create(void);

/**
 * Create identity handler context with custom configuration
 *
 * @param config    Configuration settings
 * @param tracker   Existing tracker to use (NULL to create new)
 * @return          New context, or NULL on error
 */
identity_handler_ctx_t *identity_handler_create_ex(
    const identity_handler_config_t *config,
    identity_tracker_t *tracker);

/**
 * Destroy identity handler context
 */
void identity_handler_destroy(identity_handler_ctx_t *ctx);

/**
 * Get default configuration
 */
void identity_handler_default_config(identity_handler_config_t *config);

/**
 * Get statistics
 */
void identity_handler_get_stats(const identity_handler_ctx_t *ctx,
                                 identity_handler_stats_t *stats);

/**
 * Reset statistics
 */
void identity_handler_reset_stats(identity_handler_ctx_t *ctx);

/**
 * Print statistics summary
 */
void identity_handler_print_stats(const identity_handler_ctx_t *ctx, FILE *out);

/**
 * Get the identity tracker from context
 */
identity_tracker_t *identity_handler_get_tracker(identity_handler_ctx_t *ctx);

/*============================================================================
 * Data Handler Callbacks
 *============================================================================*/

/**
 * Main paging handler callback
 * Register with: data_handler_register(DATA_TYPE_PAGING, handler_paging_identity, ctx, name)
 *
 * @param data  Decoded paging data
 * @param ctx   identity_handler_ctx_t pointer
 */
void handler_paging_identity(const decoded_data_t *data, void *ctx);

/**
 * MIB handler callback - extracts cell info
 * Register with: data_handler_register(DATA_TYPE_MIB, handler_mib_info, ctx, name)
 */
void handler_mib_info(const decoded_data_t *data, void *ctx);

/**
 * SIB1 handler callback - extracts cell info (PLMN, TAC, Cell ID)
 * Register with: data_handler_register(DATA_TYPE_SIB1, handler_sib1_info, ctx, name)
 */
void handler_sib1_info(const decoded_data_t *data, void *ctx);

/**
 * SIB2 handler callback - extracts system config
 * Register with: data_handler_register(DATA_TYPE_SIB2, handler_sib2_info, ctx, name)
 */
void handler_sib2_info(const decoded_data_t *data, void *ctx);

/*============================================================================
 * Convenience Functions
 *============================================================================*/

/**
 * Register all identity-related handlers at once
 *
 * @param ctx   identity_handler_ctx_t pointer
 * @return      0 on success, -1 on error
 */
int identity_handler_register_all(identity_handler_ctx_t *ctx);

/**
 * Unregister all identity-related handlers
 *
 * @param ctx   identity_handler_ctx_t pointer
 */
void identity_handler_unregister_all(identity_handler_ctx_t *ctx);

/*============================================================================
 * Cell Info Context (for MIB/SIB handlers)
 *============================================================================*/

typedef struct {
    /* Current cell info from MIB */
    mib_info_t current_mib;
    bool mib_valid;

    /* Current cell info from SIB1 */
    sib1_info_t current_sib1;
    bool sib1_valid;

    /* Current cell info from SIB2 */
    sib2_info_t current_sib2;
    bool sib2_valid;

    /* Derived info */
    uint16_t current_pci;       /* Physical Cell ID */
    uint16_t current_tac;       /* Tracking Area Code */
    uint32_t current_cell_id;   /* E-UTRAN Cell ID */
    uint16_t current_mcc;       /* Mobile Country Code */
    uint16_t current_mnc;       /* Mobile Network Code */

    /* Log file for cell info */
    FILE *log_file;
    bool log_json;
} cell_info_ctx_t;

/**
 * Create cell info context
 */
cell_info_ctx_t *cell_info_ctx_create(void);

/**
 * Destroy cell info context
 */
void cell_info_ctx_destroy(cell_info_ctx_t *ctx);

/**
 * Print current cell info
 */
void cell_info_print(const cell_info_ctx_t *ctx, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* HANDLER_IDENTITY_H */
