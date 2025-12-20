/**
 * sib_parser.h - LTE System Information Block parsing and scheduling
 *
 * Provides parsing of SIB1 to extract SI scheduling information,
 * and calculation of SI windows for SIB2 capture.
 *
 * Based on 3GPP TS 36.331 - RRC Protocol Specification
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef SIB_PARSER_H
#define SIB_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

#define MAX_SI_MESSAGES     32
#define MAX_SIBS_PER_SI     8
#define MAX_PLMN_IDS        6

/*============================================================================
 * SI Periodicity (3GPP TS 36.331)
 *============================================================================*/

typedef enum {
    SI_PERIODICITY_RF8   = 8,
    SI_PERIODICITY_RF16  = 16,
    SI_PERIODICITY_RF32  = 32,
    SI_PERIODICITY_RF64  = 64,
    SI_PERIODICITY_RF128 = 128,
    SI_PERIODICITY_RF256 = 256,
    SI_PERIODICITY_RF512 = 512
} si_periodicity_t;

/*============================================================================
 * SI Window Length (3GPP TS 36.331)
 *============================================================================*/

typedef enum {
    SI_WINDOW_MS1  = 1,
    SI_WINDOW_MS2  = 2,
    SI_WINDOW_MS5  = 5,
    SI_WINDOW_MS10 = 10,
    SI_WINDOW_MS15 = 15,
    SI_WINDOW_MS20 = 20,
    SI_WINDOW_MS40 = 40,
    SI_WINDOW_MS80 = 80
} si_window_length_t;

/*============================================================================
 * Data Structures
 *============================================================================*/

/**
 * PLMN Identity (Mobile Country Code + Mobile Network Code)
 */
typedef struct {
    uint16_t mcc;           /* Mobile Country Code (3 digits) */
    uint16_t mnc;           /* Mobile Network Code (2-3 digits) */
    bool     mnc_3_digits;  /* true if MNC has 3 digits */
} plmn_id_t;

/**
 * Scheduling information for a single SI message
 */
typedef struct {
    si_periodicity_t periodicity;           /* How often SI is transmitted */
    uint8_t          sib_types[MAX_SIBS_PER_SI];  /* SIB types in this SI (3-13) */
    uint8_t          num_sibs;              /* Number of SIBs in this SI */
} scheduling_info_t;

/**
 * Parsed SIB1 information
 */
typedef struct {
    /* Cell Access Related Info */
    plmn_id_t plmn_ids[MAX_PLMN_IDS];
    uint8_t   num_plmn_ids;
    uint16_t  tac;                          /* Tracking Area Code */
    uint32_t  cell_id;                      /* Cell Identity (28 bits) */
    bool      cell_barred;
    bool      intra_freq_reselection_allowed;

    /* SI Scheduling */
    si_window_length_t si_window_length;
    scheduling_info_t  si_scheduling[MAX_SI_MESSAGES];
    uint8_t            num_si_messages;

    /* SIB2 location (derived from scheduling) */
    bool    sib2_found;
    uint8_t sib2_si_index;                  /* Which SI message contains SIB2 */

    /* Parse status */
    bool    valid;
    char    error_msg[64];
} sib1_info_t;

/**
 * SI transmission window
 */
typedef struct {
    uint32_t start_sfn;         /* Starting System Frame Number */
    uint8_t  start_subframe;    /* Starting subframe index (0-9) */
    uint32_t end_sfn;           /* Ending System Frame Number */
    uint8_t  end_subframe;      /* Ending subframe index */
} si_window_t;

/**
 * SIB2 key parameters (subset of full SIB2)
 */
typedef struct {
    /* Access Barring Info */
    bool ac_barring_for_emergency;
    bool ac_barring_for_mo_signalling_present;
    bool ac_barring_for_mo_data_present;

    /* Radio Resource Config Common */
    uint8_t  prach_config_index;
    uint8_t  prach_freq_offset;
    int8_t   reference_signal_power;        /* -60 to 50 dBm */
    uint8_t  p_b;                           /* 0-3 */

    /* UE Timers and Constants */
    uint16_t t300;                          /* ms */
    uint16_t t301;                          /* ms */
    uint16_t t310;                          /* ms */
    uint16_t t311;                          /* ms */
    uint8_t  n310;
    uint8_t  n311;

    /* Frequency Info */
    uint16_t ul_carrier_freq;               /* EARFCN */
    uint8_t  ul_bandwidth;                  /* 0=6, 1=15, 2=25, 3=50, 4=75, 5=100 RBs */

    /* Parse status */
    bool valid;
} sib2_info_t;

/*============================================================================
 * Bit Reader Utility
 *============================================================================*/

typedef struct {
    const uint8_t *data;
    uint32_t       len;         /* Length in bytes */
    uint32_t       bit_pos;     /* Current bit position */
} bit_reader_t;

/**
 * Initialize bit reader
 */
void bit_reader_init(bit_reader_t *br, const uint8_t *data, uint32_t len);

/**
 * Read n bits from bit reader
 * @param br     Bit reader
 * @param n_bits Number of bits to read (1-32)
 * @return       Value read
 */
uint32_t bit_reader_read(bit_reader_t *br, uint8_t n_bits);

/**
 * Skip n bits
 */
void bit_reader_skip(bit_reader_t *br, uint32_t n_bits);

/**
 * Get remaining bits
 */
uint32_t bit_reader_remaining(const bit_reader_t *br);

/**
 * Check if reader has at least n bits remaining
 */
bool bit_reader_has_bits(const bit_reader_t *br, uint32_t n_bits);

/*============================================================================
 * SIB1 Parsing Functions
 *============================================================================*/

/**
 * Parse SIB1 payload to extract scheduling and cell information
 *
 * @param payload     Raw SIB1 payload bytes
 * @param len         Payload length in bytes
 * @param info        Output: parsed SIB1 information
 * @return            0 on success, -1 on parse error
 */
int sib1_parse(const uint8_t *payload, uint32_t len, sib1_info_t *info);

/**
 * Quick parse of SIB1 to extract only SI scheduling
 * Faster than full parse when only scheduling info is needed
 *
 * @param payload     Raw SIB1 payload bytes
 * @param len         Payload length in bytes
 * @param info        Output: scheduling info populated, other fields zeroed
 * @return            0 on success, -1 on error
 */
int sib1_parse_scheduling_only(const uint8_t *payload, uint32_t len, sib1_info_t *info);

/*============================================================================
 * SI Window Calculation (3GPP TS 36.331 Section 5.2.3)
 *============================================================================*/

/**
 * Calculate next SI transmission window for a given SI message
 *
 * Per 3GPP TS 36.331:
 * - SI message n is transmitted in radio frames satisfying:
 *   SFN mod T = FLOOR((n-1) * W / 10)
 *   where T = si-Periodicity, W = si-WindowLength
 *
 * @param sib1        Parsed SIB1 info containing scheduling
 * @param si_index    SI message index (0-based)
 * @param current_sfn Current System Frame Number
 * @param window      Output: calculated SI window
 */
void si_window_calculate(const sib1_info_t *sib1, uint8_t si_index,
                         uint32_t current_sfn, si_window_t *window);

/**
 * Calculate next SIB2 transmission window
 * Convenience function that uses SIB2 index from parsed SIB1
 *
 * @param sib1        Parsed SIB1 info
 * @param current_sfn Current System Frame Number
 * @param window      Output: calculated window
 * @return            0 on success, -1 if SIB2 not scheduled
 */
int sib2_window_calculate(const sib1_info_t *sib1, uint32_t current_sfn,
                          si_window_t *window);

/**
 * Check if current time is within an SI window
 *
 * @param window      SI window
 * @param sfn         Current SFN
 * @param subframe    Current subframe (0-9)
 * @return            true if within window
 */
bool si_window_is_active(const si_window_t *window, uint32_t sfn, uint8_t subframe);

/**
 * Get time until SI window starts (in subframes)
 *
 * @param window      SI window
 * @param sfn         Current SFN
 * @param subframe    Current subframe
 * @return            Subframes until window, 0 if already in window
 */
uint32_t si_window_time_until(const si_window_t *window, uint32_t sfn, uint8_t subframe);

/*============================================================================
 * SIB2 Parsing Functions
 *============================================================================*/

/**
 * Parse SIB2 payload to extract system configuration
 *
 * @param payload     Raw SIB2 payload bytes
 * @param len         Payload length in bytes
 * @param info        Output: parsed SIB2 information
 * @return            0 on success, -1 on parse error
 */
int sib2_parse(const uint8_t *payload, uint32_t len, sib2_info_t *info);

/*============================================================================
 * Debug/Print Functions
 *============================================================================*/

/**
 * Print SIB1 info to file
 */
void sib1_print(const sib1_info_t *info, FILE *out);

/**
 * Print SIB2 info to file
 */
void sib2_print(const sib2_info_t *info, FILE *out);

/**
 * Print SI window to file
 */
void si_window_print(const si_window_t *window, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* SIB_PARSER_H */
