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
#include <stdio.h>

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
 * Access Barring Configuration (SIB2)
 */
typedef struct {
    uint8_t  ac_barring_factor;      /* 0-15 maps to p00-p95 */
    uint16_t ac_barring_time;        /* 0=4, 1=8, 2=16, ..., 7=512 seconds */
    uint8_t  ac_barring_for_special; /* Bitmask for access classes 11-15 */
} ac_barring_config_t;

/**
 * PRACH Configuration (SIB2)
 */
typedef struct {
    uint8_t  root_sequence_index;    /* 0-837 */
    uint8_t  prach_config_index;     /* 0-63 */
    bool     high_speed_flag;        /* false = unrestricted, true = restricted */
    uint8_t  zero_correlation_zone;  /* 0-15 */
    uint8_t  prach_freq_offset;      /* 0-94 */
} prach_config_t;

/**
 * SIB2 key parameters (complete structure)
 */
typedef struct {
    /* Access Barring Info */
    bool ac_barring_for_emergency;
    bool ac_barring_for_mo_signalling_present;
    bool ac_barring_for_mo_data_present;
    ac_barring_config_t ac_barring_mo_signalling;
    ac_barring_config_t ac_barring_mo_data;

    /* RACH Config Common */
    uint8_t  preamble_init_rcvd_target_pwr;  /* -120 to -90 dBm */
    uint8_t  preamble_trans_max;             /* 3-200 transmissions */
    uint8_t  power_ramping_step;             /* 0, 2, 4, 6 dB */
    uint8_t  ra_response_window_size;        /* SF2-SF10 */
    uint8_t  mac_contention_resolution_timer; /* SF8-SF64 */
    uint8_t  max_harq_msg3_tx;               /* 1-8 */

    /* PRACH Config */
    prach_config_t prach_config;

    /* PDSCH Config Common */
    int8_t   reference_signal_power;         /* -60 to 50 dBm */
    uint8_t  p_b;                            /* 0-3 */

    /* PUSCH Config Common */
    uint8_t  n_sb;                           /* 1-4 (number of sub-bands) */
    uint8_t  hopping_mode;                   /* 0=inter, 1=intra subframe */
    uint8_t  pusch_hopping_offset;           /* 0-98 */
    bool     enable_64qam;

    /* PUCCH Config Common */
    uint8_t  delta_pucch_shift;              /* 1-3 */
    uint8_t  n_rb_cqi;                       /* 0-98 */
    uint8_t  n_cs_an;                        /* 0-7 */
    uint16_t n1_pucch_an;                    /* 0-2047 */

    /* SRS Config Common */
    bool     srs_enabled;
    uint8_t  srs_bandwidth_config;           /* 0-7 */
    uint8_t  srs_subframe_config;            /* 0-15 */
    bool     ack_nack_simultaneous_tx;

    /* Uplink Power Control */
    int8_t   p0_nominal_pusch;               /* -126 to 24 dBm */
    uint8_t  alpha;                          /* 0-8 maps to 0-1.0 */
    int8_t   p0_nominal_pucch;               /* -127 to -96 dBm */
    int8_t   delta_preamble_msg3;            /* -1 to 6 dB */

    /* UE Timers and Constants */
    uint16_t t300;                           /* ms: 100-2000 */
    uint16_t t301;                           /* ms: 100-2000 */
    uint16_t t310;                           /* ms: 0-6000 */
    uint16_t t311;                           /* ms: 1000-30000 */
    uint8_t  n310;                           /* 1-20 */
    uint8_t  n311;                           /* 1-10 */

    /* Frequency Info */
    uint32_t ul_carrier_freq;                /* EARFCN */
    uint8_t  ul_bandwidth;                   /* 0=6, 1=15, 2=25, 3=50, 4=75, 5=100 RBs */
    uint8_t  additional_spectrum_emission;   /* 1-32 */

    /* MBSFN Subframe Config (optional) */
    bool     mbsfn_present;
    uint8_t  mbsfn_subframe_allocation[6];   /* Allocation bitmap */

    /* Time Alignment Timer */
    uint16_t time_alignment_timer;           /* 500-infinity ms */

    /* Parse status */
    bool valid;
} sib2_info_t;

/**
 * SIB3 - Intra-frequency cell reselection information
 */
typedef struct {
    /* Cell Reselection Info Common */
    int8_t   q_hyst;                    /* 0-24 dB in steps */
    bool     speed_state_reselection_present;

    /* Cell Reselection Serving Freq Info */
    uint8_t  s_non_intra_search;        /* 0-31 dB */
    uint8_t  thresh_serving_low;        /* 0-31 dB */
    uint8_t  cell_reselection_priority; /* 0-7 */

    /* Intra Freq Cell Reselection Info */
    int8_t   q_rxlevmin;                /* -70 to -22 dBm */
    int8_t   p_max;                     /* -30 to 33 dBm (optional) */
    bool     p_max_present;
    uint8_t  s_intra_search;            /* 0-31 dB */
    bool     allowed_meas_bandwidth_present;
    uint8_t  allowed_meas_bandwidth;    /* 6, 15, 25, 50, 75, 100 RBs */
    bool     presence_antenna_port1;
    uint8_t  neigh_cell_config;         /* 2 bits */
    uint8_t  t_reselection_eutra;       /* 0-7 seconds */

    /* Speed State Scale Factors (optional) */
    bool     t_reselection_sf_present;
    uint8_t  t_reselection_sf_medium;   /* 0.25, 0.5, 0.75, 1.0 */
    uint8_t  t_reselection_sf_high;

    /* Parse status */
    bool valid;
} sib3_info_t;

/**
 * Intra-frequency neighboring cell info (for SIB4)
 */
typedef struct {
    uint16_t phys_cell_id;              /* Physical Cell ID (0-503) */
    int8_t   q_offset;                  /* -24 to 24 dB */
} intra_freq_neigh_cell_t;

/**
 * Intra-frequency blacklist cell (for SIB4)
 */
typedef struct {
    uint16_t phys_cell_id_start;        /* Start of PCI range */
    uint8_t  phys_cell_id_range;        /* Range (optional, 0=single) */
} intra_freq_black_cell_t;

#define MAX_INTRA_FREQ_NEIGH_CELLS  16
#define MAX_INTRA_FREQ_BLACK_CELLS  16

/**
 * SIB4 - Intra-frequency neighboring cell information
 */
typedef struct {
    /* Intra-frequency neighboring cells */
    intra_freq_neigh_cell_t neigh_cells[MAX_INTRA_FREQ_NEIGH_CELLS];
    uint8_t num_neigh_cells;

    /* Intra-frequency blacklisted cells */
    intra_freq_black_cell_t black_cells[MAX_INTRA_FREQ_BLACK_CELLS];
    uint8_t num_black_cells;

    /* CSG Physical Cell ID Range (optional) */
    bool    csg_pci_range_present;
    uint16_t csg_pci_start;
    uint8_t  csg_pci_range;

    /* Parse status */
    bool valid;
} sib4_info_t;

/**
 * Inter-frequency carrier info (for SIB5)
 */
typedef struct {
    uint32_t dl_carrier_freq;           /* EARFCN */
    int8_t   q_rxlevmin;                /* -70 to -22 dBm */
    int8_t   p_max;                     /* -30 to 33 dBm (optional) */
    bool     p_max_present;
    uint8_t  t_reselection_eutra;       /* 0-7 seconds */
    uint8_t  thresh_x_high;             /* 0-31 dB */
    uint8_t  thresh_x_low;              /* 0-31 dB */
    uint8_t  allowed_meas_bandwidth;    /* 6, 15, 25, 50, 75, 100 RBs */
    bool     presence_antenna_port1;
    uint8_t  cell_reselection_priority; /* 0-7 (optional) */
    bool     priority_present;
    uint8_t  neigh_cell_config;         /* 2 bits */
    int8_t   q_offset_freq;             /* -24 to 24 dB */
} inter_freq_carrier_t;

#define MAX_INTER_FREQ_CARRIERS  8

/**
 * SIB5 - Inter-frequency cell reselection information
 */
typedef struct {
    /* Inter-frequency carrier list */
    inter_freq_carrier_t carriers[MAX_INTER_FREQ_CARRIERS];
    uint8_t num_carriers;

    /* Parse status */
    bool valid;
} sib5_info_t;

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
 * SIB3 Parsing Functions
 *============================================================================*/

/**
 * Parse SIB3 payload to extract intra-frequency cell reselection info
 *
 * @param payload     Raw SIB3 payload bytes
 * @param len         Payload length in bytes
 * @param info        Output: parsed SIB3 information
 * @return            0 on success, -1 on parse error
 */
int sib3_parse(const uint8_t *payload, uint32_t len, sib3_info_t *info);

/*============================================================================
 * SIB4 Parsing Functions
 *============================================================================*/

/**
 * Parse SIB4 payload to extract intra-frequency neighbor cell info
 *
 * @param payload     Raw SIB4 payload bytes
 * @param len         Payload length in bytes
 * @param info        Output: parsed SIB4 information
 * @return            0 on success, -1 on parse error
 */
int sib4_parse(const uint8_t *payload, uint32_t len, sib4_info_t *info);

/*============================================================================
 * SIB5 Parsing Functions
 *============================================================================*/

/**
 * Parse SIB5 payload to extract inter-frequency cell reselection info
 *
 * @param payload     Raw SIB5 payload bytes
 * @param len         Payload length in bytes
 * @param info        Output: parsed SIB5 information
 * @return            0 on success, -1 on parse error
 */
int sib5_parse(const uint8_t *payload, uint32_t len, sib5_info_t *info);

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
 * Print SIB3 info to file
 */
void sib3_print(const sib3_info_t *info, FILE *out);

/**
 * Print SIB4 info to file
 */
void sib4_print(const sib4_info_t *info, FILE *out);

/**
 * Print SIB5 info to file
 */
void sib5_print(const sib5_info_t *info, FILE *out);

/**
 * Print SI window to file
 */
void si_window_print(const si_window_t *window, FILE *out);

/*============================================================================
 * JSON Formatting Functions
 *============================================================================*/

/**
 * Format SIB1 as JSON string
 */
int sib1_to_json(const sib1_info_t *info, char *buf, size_t buf_len);

/**
 * Format SIB2 as JSON string
 */
int sib2_to_json(const sib2_info_t *info, char *buf, size_t buf_len);

/**
 * Format SIB3 as JSON string
 */
int sib3_to_json(const sib3_info_t *info, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* SIB_PARSER_H */
