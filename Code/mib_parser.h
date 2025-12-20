/**
 * mib_parser.h - LTE Master Information Block parsing
 *
 * Provides parsing of the Master Information Block (MIB) transmitted
 * on the BCH (Broadcast Channel) within PBCH (Physical Broadcast Channel).
 *
 * Based on 3GPP TS 36.331 - RRC Protocol Specification
 * Based on 3GPP TS 36.212 - Multiplexing and channel coding
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef MIB_PARSER_H
#define MIB_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

#define MIB_PAYLOAD_LEN     3   /* 24 bits = 3 bytes */

/*============================================================================
 * DL Bandwidth (3GPP TS 36.101)
 *============================================================================*/

typedef enum {
    DL_BANDWIDTH_6   = 0,   /* 1.4 MHz - 6 RBs */
    DL_BANDWIDTH_15  = 1,   /* 3 MHz - 15 RBs */
    DL_BANDWIDTH_25  = 2,   /* 5 MHz - 25 RBs */
    DL_BANDWIDTH_50  = 3,   /* 10 MHz - 50 RBs */
    DL_BANDWIDTH_75  = 4,   /* 15 MHz - 75 RBs */
    DL_BANDWIDTH_100 = 5    /* 20 MHz - 100 RBs */
} dl_bandwidth_t;

/*============================================================================
 * PHICH Configuration (3GPP TS 36.211)
 *============================================================================*/

typedef enum {
    PHICH_DURATION_NORMAL   = 0,
    PHICH_DURATION_EXTENDED = 1
} phich_duration_t;

typedef enum {
    PHICH_RESOURCE_ONESIXTH   = 0,  /* Ng = 1/6 */
    PHICH_RESOURCE_HALF       = 1,  /* Ng = 1/2 */
    PHICH_RESOURCE_ONE        = 2,  /* Ng = 1 */
    PHICH_RESOURCE_TWO        = 3   /* Ng = 2 */
} phich_resource_t;

/*============================================================================
 * MIB Structure
 *============================================================================*/

/**
 * Parsed MIB information
 *
 * MIB ASN.1 structure (3GPP TS 36.331):
 *
 * MasterInformationBlock ::= SEQUENCE {
 *   dl-Bandwidth            ENUMERATED {n6, n15, n25, n50, n75, n100},
 *   phich-Config            PHICH-Config,
 *   systemFrameNumber       BIT STRING (SIZE (8)),
 *   schedulingInfoSIB1-BR-r13 INTEGER (0..31)    OPTIONAL, -- Rel-13
 *   systemInfoUnchanged-BR-r15 BOOLEAN           OPTIONAL, -- Rel-15
 *   spare                   BIT STRING (SIZE (10 or 5))
 * }
 *
 * PHICH-Config ::= SEQUENCE {
 *   phich-Duration          ENUMERATED {normal, extended},
 *   phich-Resource          ENUMERATED {oneSixth, half, one, two}
 * }
 */
typedef struct {
    /* Downlink bandwidth (3 bits) */
    dl_bandwidth_t  dl_bandwidth;
    uint8_t         n_rb_dl;            /* Number of RBs derived from bandwidth */
    float           bandwidth_mhz;      /* Bandwidth in MHz */

    /* PHICH configuration (3 bits total) */
    phich_duration_t phich_duration;    /* Normal or extended (1 bit) */
    phich_resource_t phich_resource;    /* Ng value (2 bits) */
    float            phich_ng;          /* Ng as float (1/6, 1/2, 1, 2) */

    /* System Frame Number (8 bits) */
    uint16_t        sfn;                /* SFN bits [0:7] from MIB */
    uint8_t         sfn_offset;         /* SFN bits [8:9] from timing */

    /* Derived values */
    uint8_t         nof_ports;          /* Number of antenna ports (from PBCH) */
    uint8_t         nof_phich_groups;   /* Number of PHICH groups */

    /* Spare/reserved bits */
    uint16_t        spare_bits;         /* Spare bits for debugging */

    /* Parse status */
    bool            valid;
    uint64_t        timestamp_us;       /* When MIB was received */
    uint32_t        pci;                /* Physical Cell ID */
} mib_info_t;

/*============================================================================
 * MIB Parsing Functions
 *============================================================================*/

/**
 * Parse MIB from BCH payload
 *
 * The MIB is 24 bits encoded as follows:
 *   - Bits [0:2]:   dl-Bandwidth (3 bits)
 *   - Bit [3]:      phich-Duration (1 bit)
 *   - Bits [4:5]:   phich-Resource (2 bits)
 *   - Bits [6:13]:  systemFrameNumber (8 bits, MSB of SFN)
 *   - Bits [14]:    Reserved (1 bit)
 *   - Bits [15:23]: Spare (9 bits)
 *
 * @param payload     BCH payload (3 bytes = 24 bits)
 * @param info        Output: parsed MIB information
 * @return            0 on success, -1 on error
 */
int mib_parse(const uint8_t *payload, mib_info_t *info);

/**
 * Parse MIB from BCH payload with additional context
 *
 * @param payload     BCH payload (3 bytes)
 * @param sfn_offset  SFN offset (lower 2 bits from PBCH timing)
 * @param nof_ports   Number of antenna ports (from PBCH decoding)
 * @param pci         Physical Cell ID
 * @param info        Output: parsed MIB information
 * @return            0 on success, -1 on error
 */
int mib_parse_with_context(const uint8_t *payload, uint8_t sfn_offset,
                           uint8_t nof_ports, uint32_t pci, mib_info_t *info);

/**
 * Calculate number of PHICH groups
 *
 * Per 3GPP TS 36.211 Table 6.9-1:
 * Ngroup = ceil(Ng * (N_RB_DL / 8))  for normal CP
 *
 * @param n_rb_dl     Number of downlink RBs
 * @param phich_ng    Ng value (1/6, 1/2, 1, or 2)
 * @return            Number of PHICH groups
 */
uint8_t mib_calc_phich_groups(uint8_t n_rb_dl, float phich_ng);

/*============================================================================
 * Utility Functions
 *============================================================================*/

/**
 * Get bandwidth in MHz from dl_bandwidth enum
 */
float mib_bandwidth_to_mhz(dl_bandwidth_t bw);

/**
 * Get number of RBs from dl_bandwidth enum
 */
uint8_t mib_bandwidth_to_nrb(dl_bandwidth_t bw);

/**
 * Get Ng float value from phich_resource enum
 */
float mib_phich_resource_to_ng(phich_resource_t res);

/**
 * Get string representation of bandwidth
 */
const char *mib_bandwidth_str(dl_bandwidth_t bw);

/**
 * Get string representation of PHICH duration
 */
const char *mib_phich_duration_str(phich_duration_t dur);

/**
 * Get string representation of PHICH resource
 */
const char *mib_phich_resource_str(phich_resource_t res);

/*============================================================================
 * Debug/Print Functions
 *============================================================================*/

/**
 * Print MIB info to file
 */
void mib_print(const mib_info_t *info, FILE *out);

/**
 * Format MIB as JSON string
 *
 * @param info        MIB information
 * @param buf         Output buffer
 * @param buf_len     Buffer size
 * @return            Number of bytes written, -1 on error
 */
int mib_to_json(const mib_info_t *info, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* MIB_PARSER_H */
