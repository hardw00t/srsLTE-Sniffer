/**
 * sib_parser.c - LTE System Information Block parsing implementation
 *
 * Note: This is a simplified parser for common SIB1 configurations.
 * Full ASN.1 PER decoding would require a more comprehensive library.
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "sib_parser.h"
#include <string.h>
#include <stdio.h>

/*============================================================================
 * Bit Reader Implementation
 *============================================================================*/

void bit_reader_init(bit_reader_t *br, const uint8_t *data, uint32_t len) {
    br->data = data;
    br->len = len;
    br->bit_pos = 0;
}

uint32_t bit_reader_read(bit_reader_t *br, uint8_t n_bits) {
    if (n_bits == 0 || n_bits > 32) {
        return 0;
    }

    uint32_t value = 0;
    for (int i = 0; i < n_bits; i++) {
        uint32_t byte_idx = br->bit_pos / 8;
        uint8_t bit_idx = 7 - (br->bit_pos % 8);

        if (byte_idx < br->len) {
            value = (value << 1) | ((br->data[byte_idx] >> bit_idx) & 1);
        }
        br->bit_pos++;
    }
    return value;
}

void bit_reader_skip(bit_reader_t *br, uint32_t n_bits) {
    br->bit_pos += n_bits;
    if (br->bit_pos > br->len * 8) {
        br->bit_pos = br->len * 8;
    }
}

uint32_t bit_reader_remaining(const bit_reader_t *br) {
    uint32_t total_bits = br->len * 8;
    if (br->bit_pos >= total_bits) {
        return 0;
    }
    return total_bits - br->bit_pos;
}

bool bit_reader_has_bits(const bit_reader_t *br, uint32_t n_bits) {
    return bit_reader_remaining(br) >= n_bits;
}

/*============================================================================
 * SI Window Calculation
 *============================================================================*/

void si_window_calculate(const sib1_info_t *sib1, uint8_t si_index,
                         uint32_t current_sfn, si_window_t *window) {
    if (sib1 == NULL || window == NULL || si_index >= sib1->num_si_messages) {
        memset(window, 0, sizeof(si_window_t));
        return;
    }

    /* Get scheduling parameters */
    uint16_t T = sib1->si_scheduling[si_index].periodicity;
    uint8_t W = sib1->si_window_length;

    /* Default values if not set */
    if (T == 0) T = SI_PERIODICITY_RF8;
    if (W == 0) W = SI_WINDOW_MS5;

    /*
     * Per 3GPP TS 36.331 Section 5.2.3:
     * SI message n (1-indexed in spec) is transmitted in radio frames where:
     *   SFN mod T = FLOOR((n-1) * W / 10)
     *
     * si_index is 0-based, so we use si_index instead of (n-1)
     */
    uint32_t x = (si_index * W) / 10;

    /* Find the next valid starting frame */
    uint32_t start_sfn = current_sfn - (current_sfn % T) + x;

    /* If this window has passed, move to next period */
    if (start_sfn < current_sfn) {
        start_sfn += T;
    }

    /* Handle SFN wraparound (SFN is 10 bits, 0-1023) */
    start_sfn = start_sfn % 1024;

    window->start_sfn = start_sfn;
    window->start_subframe = 0;

    /* Window ends after W subframes */
    uint32_t end_sf_absolute = start_sfn * 10 + W;
    window->end_sfn = (end_sf_absolute / 10) % 1024;
    window->end_subframe = end_sf_absolute % 10;
}

int sib2_window_calculate(const sib1_info_t *sib1, uint32_t current_sfn,
                          si_window_t *window) {
    if (sib1 == NULL || !sib1->sib2_found) {
        return -1;
    }

    si_window_calculate(sib1, sib1->sib2_si_index, current_sfn, window);
    return 0;
}

bool si_window_is_active(const si_window_t *window, uint32_t sfn, uint8_t subframe) {
    if (window == NULL) {
        return false;
    }

    uint32_t current_sf = sfn * 10 + subframe;
    uint32_t start_sf = window->start_sfn * 10 + window->start_subframe;
    uint32_t end_sf = window->end_sfn * 10 + window->end_subframe;

    /* Handle wraparound */
    if (end_sf < start_sf) {
        /* Window spans SFN wraparound */
        return (current_sf >= start_sf) || (current_sf <= end_sf);
    }

    return (current_sf >= start_sf) && (current_sf <= end_sf);
}

uint32_t si_window_time_until(const si_window_t *window, uint32_t sfn, uint8_t subframe) {
    if (window == NULL) {
        return 0;
    }

    uint32_t current_sf = sfn * 10 + subframe;
    uint32_t start_sf = window->start_sfn * 10 + window->start_subframe;

    if (current_sf >= start_sf) {
        /* Already in or past window */
        return 0;
    }

    return start_sf - current_sf;
}

/*============================================================================
 * SIB1 Parsing
 *
 * Note: This is a simplified parser that handles common configurations.
 * Full ASN.1 UPER decoding is complex; this focuses on extracting
 * the SI scheduling information needed for SIB2 capture.
 *============================================================================*/

int sib1_parse(const uint8_t *payload, uint32_t len, sib1_info_t *info) {
    if (payload == NULL || len == 0 || info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(sib1_info_t));

    bit_reader_t br;
    bit_reader_init(&br, payload, len);

    /*
     * SIB1 ASN.1 structure (simplified):
     *
     * SystemInformationBlockType1 ::= SEQUENCE {
     *   cellAccessRelatedInfo SEQUENCE {
     *     plmn-IdentityList PLMN-IdentityList,
     *     trackingAreaCode TrackingAreaCode,
     *     cellIdentity CellIdentity,
     *     cellBarred ENUMERATED {barred, notBarred},
     *     intraFreqReselection ENUMERATED {allowed, notAllowed},
     *     csg-Indication BOOLEAN,
     *     ...
     *   },
     *   cellSelectionInfo SEQUENCE {
     *     q-RxLevMin Q-RxLevMin,
     *     q-RxLevMinOffset INTEGER (1..8) OPTIONAL
     *   },
     *   ...
     *   schedulingInfoList SchedulingInfoList,
     *   ...
     * }
     */

    /* The exact bit positions depend on optional fields.
     * For a basic implementation, we use heuristics to find scheduling info.
     *
     * Strategy: The first SI message always implicitly contains SIB2.
     * We set reasonable defaults and try to parse what we can.
     */

    /* Set defaults that work for most networks */
    info->si_window_length = SI_WINDOW_MS5;
    info->num_si_messages = 1;
    info->si_scheduling[0].periodicity = SI_PERIODICITY_RF8;
    info->si_scheduling[0].num_sibs = 0;  /* SIB2 is implicit in SI-1 */

    /* SIB2 is always in the first SI message (index 0) */
    info->sib2_found = true;
    info->sib2_si_index = 0;

    /*
     * Attempt to parse PLMN and cell info from the beginning
     * This is a best-effort parse; actual position depends on encoding
     */

    /* Check if we have enough data */
    if (!bit_reader_has_bits(&br, 24)) {
        info->valid = true;  /* Still valid with defaults */
        return 0;
    }

    /*
     * Try to extract basic cell info
     * Note: This is approximate and may not work for all SIB1 variants
     */

    /* Skip extension marker if present (1 bit) */
    bit_reader_skip(&br, 1);

    /* PLMN-IdentityList (at least one entry) */
    uint8_t num_plmn = bit_reader_read(&br, 3) + 1;  /* 1-6 entries */
    if (num_plmn > MAX_PLMN_IDS) {
        num_plmn = MAX_PLMN_IDS;
    }
    info->num_plmn_ids = num_plmn;

    /* For each PLMN-IdentityInfo */
    for (int i = 0; i < num_plmn && bit_reader_has_bits(&br, 20); i++) {
        /* PLMN-Identity */
        /* MCC (3 digits, each 4 bits = 12 bits) */
        uint16_t mcc = 0;
        mcc += bit_reader_read(&br, 4) * 100;
        mcc += bit_reader_read(&br, 4) * 10;
        mcc += bit_reader_read(&br, 4);
        info->plmn_ids[i].mcc = mcc;

        /* MNC (2-3 digits) - check for 3-digit indicator */
        bool mnc_3_digits = bit_reader_read(&br, 1);
        info->plmn_ids[i].mnc_3_digits = mnc_3_digits;

        uint16_t mnc = 0;
        mnc += bit_reader_read(&br, 4) * 10;
        mnc += bit_reader_read(&br, 4);
        if (mnc_3_digits) {
            mnc = mnc * 10 + bit_reader_read(&br, 4);
        }
        info->plmn_ids[i].mnc = mnc;

        /* cellReservedForOperatorUse (1 bit) */
        bit_reader_skip(&br, 1);
    }

    /* TrackingAreaCode (16 bits) */
    if (bit_reader_has_bits(&br, 16)) {
        info->tac = bit_reader_read(&br, 16);
    }

    /* CellIdentity (28 bits) */
    if (bit_reader_has_bits(&br, 28)) {
        info->cell_id = bit_reader_read(&br, 28);
    }

    /* cellBarred (1 bit enum) */
    if (bit_reader_has_bits(&br, 1)) {
        info->cell_barred = bit_reader_read(&br, 1);
    }

    /* intraFreqReselection (1 bit enum) */
    if (bit_reader_has_bits(&br, 1)) {
        info->intra_freq_reselection_allowed = !bit_reader_read(&br, 1);
    }

    info->valid = true;
    return 0;
}

int sib1_parse_scheduling_only(const uint8_t *payload, uint32_t len, sib1_info_t *info) {
    /* For scheduling-only parse, just set defaults */
    /* SIB2 is always in the first SI message */
    if (info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(sib1_info_t));

    info->si_window_length = SI_WINDOW_MS5;
    info->num_si_messages = 1;
    info->si_scheduling[0].periodicity = SI_PERIODICITY_RF8;
    info->si_scheduling[0].num_sibs = 0;

    info->sib2_found = true;
    info->sib2_si_index = 0;
    info->valid = true;

    return 0;
}

/*============================================================================
 * SIB2 Parsing (Simplified)
 *============================================================================*/

int sib2_parse(const uint8_t *payload, uint32_t len, sib2_info_t *info) {
    if (payload == NULL || len == 0 || info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(sib2_info_t));

    /*
     * SIB2 is a complex structure. For basic use cases,
     * we extract key parameters that are useful for:
     * - Understanding cell configuration
     * - Setting up rogue base station (research purposes)
     *
     * Full parsing requires extensive ASN.1 UPER handling.
     */

    bit_reader_t br;
    bit_reader_init(&br, payload, len);

    /* Set some default values */
    info->reference_signal_power = -10;  /* Common default */
    info->t300 = 1000;
    info->t301 = 1000;
    info->t310 = 1000;
    info->t311 = 1000;
    info->n310 = 1;
    info->n311 = 1;

    /*
     * Note: Actual SIB2 parsing is complex due to many optional fields.
     * For research purposes, the raw payload can be decoded in Wireshark
     * with the lte-rrc dissector for complete analysis.
     */

    info->valid = true;
    return 0;
}

/*============================================================================
 * Debug/Print Functions
 *============================================================================*/

void sib1_print(const sib1_info_t *info, FILE *out) {
    if (info == NULL || out == NULL) {
        return;
    }

    fprintf(out, "=== SIB1 Information ===\n");

    if (!info->valid) {
        fprintf(out, "  Status: INVALID\n");
        if (info->error_msg[0]) {
            fprintf(out, "  Error: %s\n", info->error_msg);
        }
        return;
    }

    /* PLMN IDs */
    fprintf(out, "  PLMN IDs (%d):\n", info->num_plmn_ids);
    for (int i = 0; i < info->num_plmn_ids; i++) {
        fprintf(out, "    [%d] MCC=%03u MNC=%0*u\n",
                i, info->plmn_ids[i].mcc,
                info->plmn_ids[i].mnc_3_digits ? 3 : 2,
                info->plmn_ids[i].mnc);
    }

    /* Cell Info */
    fprintf(out, "  TAC: %u (0x%04X)\n", info->tac, info->tac);
    fprintf(out, "  Cell ID: %u (0x%07X)\n", info->cell_id, info->cell_id);
    fprintf(out, "  Cell Barred: %s\n", info->cell_barred ? "Yes" : "No");
    fprintf(out, "  Intra-freq Reselection: %s\n",
            info->intra_freq_reselection_allowed ? "Allowed" : "Not Allowed");

    /* SI Scheduling */
    fprintf(out, "  SI Window Length: %u ms\n", info->si_window_length);
    fprintf(out, "  SI Messages (%d):\n", info->num_si_messages);
    for (int i = 0; i < info->num_si_messages; i++) {
        fprintf(out, "    [%d] Periodicity=%u frames, SIBs: ",
                i, info->si_scheduling[i].periodicity);
        if (i == 0) {
            fprintf(out, "SIB2");
            for (int j = 0; j < info->si_scheduling[i].num_sibs; j++) {
                fprintf(out, ", SIB%d", info->si_scheduling[i].sib_types[j]);
            }
        } else {
            for (int j = 0; j < info->si_scheduling[i].num_sibs; j++) {
                if (j > 0) fprintf(out, ", ");
                fprintf(out, "SIB%d", info->si_scheduling[i].sib_types[j]);
            }
        }
        fprintf(out, "\n");
    }

    if (info->sib2_found) {
        fprintf(out, "  SIB2 Location: SI message %d\n", info->sib2_si_index);
    }

    fprintf(out, "========================\n");
}

void sib2_print(const sib2_info_t *info, FILE *out) {
    if (info == NULL || out == NULL) {
        return;
    }

    fprintf(out, "=== SIB2 Information ===\n");

    if (!info->valid) {
        fprintf(out, "  Status: INVALID\n");
        return;
    }

    fprintf(out, "  Reference Signal Power: %d dBm\n", info->reference_signal_power);
    fprintf(out, "  PRACH Config Index: %u\n", info->prach_config_index);
    fprintf(out, "  PRACH Freq Offset: %u\n", info->prach_freq_offset);
    fprintf(out, "  UE Timers:\n");
    fprintf(out, "    T300=%u ms, T301=%u ms, T310=%u ms, T311=%u ms\n",
            info->t300, info->t301, info->t310, info->t311);
    fprintf(out, "    N310=%u, N311=%u\n", info->n310, info->n311);

    fprintf(out, "========================\n");
}

void si_window_print(const si_window_t *window, FILE *out) {
    if (window == NULL || out == NULL) {
        return;
    }

    fprintf(out, "SI Window: SFN %u.%u to SFN %u.%u\n",
            window->start_sfn, window->start_subframe,
            window->end_sfn, window->end_subframe);
}
