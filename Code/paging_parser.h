/**
 * paging_parser.h - LTE Paging Message parsing
 *
 * Provides parsing of paging messages to extract UE identities
 * (IMSI, S-TMSI) and paging causes.
 *
 * Based on 3GPP TS 36.331 - RRC Protocol Specification
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef PAGING_PARSER_H
#define PAGING_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

#define IMSI_MAX_DIGITS         15
#define STMSI_LEN               5   /* 40 bits = 5 bytes */
#define STMSI_HEX_LEN           10  /* 10 hex characters */
#define MAX_PAGING_RECORDS      16

/*============================================================================
 * Paging UE Identity Types
 *============================================================================*/

typedef enum {
    PAGING_ID_STMSI = 0,    /* S-TMSI (MME Code + M-TMSI) */
    PAGING_ID_IMSI  = 1     /* Full IMSI */
} paging_id_type_t;

/*============================================================================
 * Paging Cause
 *============================================================================*/

typedef enum {
    PAGING_CAUSE_UNSPECIFIED = 0,
    PAGING_CAUSE_VOICE       = 1,   /* Voice call */
    PAGING_CAUSE_VIDEO       = 2,   /* Video call */
    PAGING_CAUSE_SMS         = 3,   /* Short message */
    PAGING_CAUSE_MPS         = 4,   /* Multimedia Priority Service */
    PAGING_CAUSE_MCS         = 5,   /* Mission Critical Services */
    PAGING_CAUSE_DELAY_TOLERANT = 6  /* Delay tolerant services */
} paging_cause_t;

/*============================================================================
 * S-TMSI Structure (3GPP TS 36.331)
 *============================================================================*/

/**
 * S-TMSI breakdown:
 *   - mmec (MME Code): 8 bits
 *   - m-TMSI: 32 bits
 * Total: 40 bits
 */
typedef struct {
    uint8_t  mmec;          /* MME Code (8 bits) */
    uint32_t m_tmsi;        /* M-TMSI (32 bits) */
    char     hex_str[STMSI_HEX_LEN + 1];  /* Hex string representation */
} stmsi_t;

/*============================================================================
 * IMSI Structure
 *============================================================================*/

typedef struct {
    char     digits[IMSI_MAX_DIGITS + 1];   /* IMSI as digit string */
    uint8_t  length;                         /* Number of digits (14-15) */
    uint16_t mcc;                            /* Mobile Country Code */
    uint16_t mnc;                            /* Mobile Network Code */
    bool     mnc_3_digits;                   /* MNC has 3 digits */
} imsi_t;

/*============================================================================
 * Paging Record Structure
 *============================================================================*/

typedef struct {
    paging_id_type_t id_type;       /* S-TMSI or IMSI */

    /* Identity (only one is valid based on id_type) */
    stmsi_t          stmsi;         /* Valid if id_type == PAGING_ID_STMSI */
    imsi_t           imsi;          /* Valid if id_type == PAGING_ID_IMSI */

    /* Optional fields */
    bool             cn_domain_present;
    uint8_t          cn_domain;     /* 0=PS, 1=CS */
    bool             paging_cause_present;
    paging_cause_t   paging_cause;
} paging_record_t;

/*============================================================================
 * Parsed Paging Message Structure
 *============================================================================*/

typedef struct {
    /* Paging records */
    paging_record_t records[MAX_PAGING_RECORDS];
    uint8_t         num_records;

    /* System information modification indicator */
    bool            si_modification;

    /* ETWS indicator */
    bool            etws_indication;

    /* CMAS indicator (Commercial Mobile Alert System) */
    bool            cmas_indication;

    /* Statistics */
    uint8_t         num_imsi;       /* Number of records with IMSI */
    uint8_t         num_stmsi;      /* Number of records with S-TMSI */

    /* Parse status */
    bool            valid;
    char            error_msg[64];

    /* Metadata */
    uint64_t        timestamp_us;
    uint32_t        sfn;
    uint8_t         subframe;
    uint16_t        cell_id;
} paging_message_t;

/*============================================================================
 * Parsing Functions
 *============================================================================*/

/**
 * Parse paging message from RRC payload
 *
 * @param payload     Raw paging message bytes
 * @param len         Payload length in bytes
 * @param msg         Output: parsed paging message
 * @return            0 on success, -1 on error
 */
int paging_parse(const uint8_t *payload, uint32_t len, paging_message_t *msg);

/**
 * Parse paging message with metadata
 *
 * @param payload     Raw paging message bytes
 * @param len         Payload length in bytes
 * @param sfn         System Frame Number
 * @param subframe    Subframe index (0-9)
 * @param cell_id     Cell ID
 * @param msg         Output: parsed paging message
 * @return            0 on success, -1 on error
 */
int paging_parse_with_context(const uint8_t *payload, uint32_t len,
                              uint32_t sfn, uint8_t subframe, uint16_t cell_id,
                              paging_message_t *msg);

/**
 * Extract IMSI from digit buffer (BCD encoded)
 *
 * IMSI encoding in paging:
 * - First byte: Type + first digit (odd length) or type (even length)
 * - Subsequent bytes: Two BCD digits per byte
 *
 * @param data        BCD encoded IMSI data
 * @param len         Data length in bytes
 * @param imsi        Output: parsed IMSI
 * @return            0 on success, -1 on error
 */
int paging_parse_imsi(const uint8_t *data, uint32_t len, imsi_t *imsi);

/**
 * Extract S-TMSI from data
 *
 * @param data        S-TMSI data (5 bytes)
 * @param stmsi       Output: parsed S-TMSI
 * @return            0 on success, -1 on error
 */
int paging_parse_stmsi(const uint8_t *data, stmsi_t *stmsi);

/*============================================================================
 * Heuristic Parsing (for non-standard payloads)
 *============================================================================*/

/**
 * Try to find and extract IMSI from payload using heuristics
 * Useful when ASN.1 structure is corrupted or truncated
 *
 * @param payload     Raw payload
 * @param len         Payload length
 * @param imsi        Output: found IMSI (if any)
 * @return            0 if IMSI found, -1 otherwise
 */
int paging_find_imsi_heuristic(const uint8_t *payload, uint32_t len, imsi_t *imsi);

/**
 * Try to find and extract S-TMSI from payload using heuristics
 *
 * @param payload     Raw payload
 * @param len         Payload length
 * @param stmsi       Output: found S-TMSI (if any)
 * @return            0 if S-TMSI found, -1 otherwise
 */
int paging_find_stmsi_heuristic(const uint8_t *payload, uint32_t len, stmsi_t *stmsi);

/*============================================================================
 * Utility Functions
 *============================================================================*/

/**
 * Format S-TMSI as hex string (from structure)
 */
void paging_stmsi_to_hex(const stmsi_t *stmsi, char *buf);

/**
 * Parse S-TMSI from hex string
 */
int paging_stmsi_from_hex(const char *hex, stmsi_t *stmsi);

/**
 * Extract MCC/MNC from IMSI structure
 */
void paging_extract_plmn(const imsi_t *imsi, uint16_t *mcc, uint16_t *mnc);

/**
 * Get paging cause as string
 */
const char *paging_cause_str(paging_cause_t cause);

/**
 * Get paging ID type as string
 */
const char *paging_id_type_str(paging_id_type_t type);

/*============================================================================
 * Debug/Print Functions
 *============================================================================*/

/**
 * Print paging message to file
 */
void paging_print(const paging_message_t *msg, FILE *out);

/**
 * Print single paging record
 */
void paging_record_print(const paging_record_t *rec, int index, FILE *out);

/**
 * Format paging message as JSON string
 *
 * @param msg         Paging message
 * @param buf         Output buffer
 * @param buf_len     Buffer size
 * @return            Number of bytes written, -1 on error
 */
int paging_to_json(const paging_message_t *msg, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* PAGING_PARSER_H */
