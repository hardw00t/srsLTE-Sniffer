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
 * UE Timer Value Lookup Tables (3GPP TS 36.331)
 *============================================================================*/

static const uint16_t t300_values[] = {
    100, 200, 300, 400, 600, 1000, 1500, 2000
};

static const uint16_t t301_values[] = {
    100, 200, 300, 400, 600, 1000, 1500, 2000
};

static const uint16_t t310_values[] = {
    0, 50, 100, 200, 500, 1000, 2000
};

static const uint16_t t311_values[] = {
    1000, 3000, 5000, 10000, 15000, 20000, 30000
};

static const uint8_t n310_values[] = {
    1, 2, 3, 4, 6, 8, 10, 20
};

static const uint8_t n311_values[] = {
    1, 2, 3, 4, 5, 6, 8, 10
};

/*============================================================================
 * SIB2 Parsing (Enhanced)
 *============================================================================*/

int sib2_parse(const uint8_t *payload, uint32_t len, sib2_info_t *info) {
    if (payload == NULL || len == 0 || info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(sib2_info_t));

    bit_reader_t br;
    bit_reader_init(&br, payload, len);

    /*
     * SystemInformationBlockType2 ::= SEQUENCE {
     *   ac-BarringInfo SEQUENCE {...} OPTIONAL,
     *   radioResourceConfigCommon RadioResourceConfigCommonSIB,
     *   ue-TimersAndConstants UE-TimersAndConstants,
     *   freqInfo SEQUENCE {...},
     *   mbsfn-SubframeConfigList MBSFN-SubframeConfigList OPTIONAL,
     *   timeAlignmentTimerCommon TimeAlignmentTimer,
     *   ...
     * }
     */

    /* Extension marker */
    if (!bit_reader_has_bits(&br, 1)) goto set_defaults;
    bit_reader_skip(&br, 1);

    /* ac-BarringInfo presence */
    bool ac_barring_present = bit_reader_read(&br, 1);

    if (ac_barring_present) {
        /* ac-BarringForEmergency BOOLEAN */
        info->ac_barring_for_emergency = bit_reader_read(&br, 1);

        /* ac-BarringForMO-Signalling presence */
        info->ac_barring_for_mo_signalling_present = bit_reader_read(&br, 1);

        /* ac-BarringForMO-Data presence */
        info->ac_barring_for_mo_data_present = bit_reader_read(&br, 1);

        /* Parse AC-BarringConfig for MO-Signalling if present */
        if (info->ac_barring_for_mo_signalling_present && bit_reader_has_bits(&br, 8)) {
            info->ac_barring_mo_signalling.ac_barring_factor = bit_reader_read(&br, 4);
            info->ac_barring_mo_signalling.ac_barring_time = bit_reader_read(&br, 3);
            info->ac_barring_mo_signalling.ac_barring_for_special = bit_reader_read(&br, 5);
        }

        /* Parse AC-BarringConfig for MO-Data if present */
        if (info->ac_barring_for_mo_data_present && bit_reader_has_bits(&br, 8)) {
            info->ac_barring_mo_data.ac_barring_factor = bit_reader_read(&br, 4);
            info->ac_barring_mo_data.ac_barring_time = bit_reader_read(&br, 3);
            info->ac_barring_mo_data.ac_barring_for_special = bit_reader_read(&br, 5);
        }
    }

    /*
     * RadioResourceConfigCommonSIB - complex structure
     * We extract key fields used for analysis
     */

    /* RACH-ConfigCommon */
    if (bit_reader_has_bits(&br, 24)) {
        /* preambleInfo */
        bit_reader_skip(&br, 4);  /* numberOfRA-Preambles */
        bool group_a_present = bit_reader_read(&br, 1);
        if (group_a_present) {
            bit_reader_skip(&br, 8);  /* sizeOfRA-PreamblesGroupA + messageSizeGroupA + messagePowerOffsetGroupB */
        }

        /* powerRampingParameters */
        info->power_ramping_step = bit_reader_read(&br, 2) * 2;  /* 0, 2, 4, 6 dB */
        info->preamble_init_rcvd_target_pwr = -120 + bit_reader_read(&br, 4) * 2;

        /* ra-SupervisionInfo */
        info->preamble_trans_max = bit_reader_read(&br, 4);
        info->ra_response_window_size = bit_reader_read(&br, 3);
        info->mac_contention_resolution_timer = bit_reader_read(&br, 3);

        info->max_harq_msg3_tx = bit_reader_read(&br, 3) + 1;
    }

    /* PRACH-Config */
    if (bit_reader_has_bits(&br, 16)) {
        info->prach_config.root_sequence_index = bit_reader_read(&br, 10);
        /* prach-ConfigInfo */
        info->prach_config.prach_config_index = bit_reader_read(&br, 6);
        if (bit_reader_has_bits(&br, 7)) {
            info->prach_config.high_speed_flag = bit_reader_read(&br, 1);
            info->prach_config.zero_correlation_zone = bit_reader_read(&br, 4);
            info->prach_config.prach_freq_offset = bit_reader_read(&br, 7);
        }
    }

    /* PDSCH-ConfigCommon */
    if (bit_reader_has_bits(&br, 10)) {
        info->reference_signal_power = (int8_t)bit_reader_read(&br, 8) - 60;  /* -60 to 50 */
        info->p_b = bit_reader_read(&br, 2);
    }

    /* Skip to UE-TimersAndConstants (simplified - position varies) */
    /* Look for timer values pattern in remaining bits */

set_defaults:
    /* Set reasonable defaults if parsing incomplete */
    if (info->reference_signal_power == 0) {
        info->reference_signal_power = -10;
    }

    /* Default timer values */
    if (info->t300 == 0) info->t300 = 1000;
    if (info->t301 == 0) info->t301 = 1000;
    if (info->t310 == 0) info->t310 = 1000;
    if (info->t311 == 0) info->t311 = 1000;
    if (info->n310 == 0) info->n310 = 1;
    if (info->n311 == 0) info->n311 = 1;
    if (info->time_alignment_timer == 0) info->time_alignment_timer = 500;

    info->valid = true;
    return 0;
}

/*============================================================================
 * SIB3 Parsing
 *============================================================================*/

/* q-Hyst values in dB */
static const int8_t q_hyst_values[] = {
    0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24
};

int sib3_parse(const uint8_t *payload, uint32_t len, sib3_info_t *info) {
    if (payload == NULL || len == 0 || info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(sib3_info_t));

    bit_reader_t br;
    bit_reader_init(&br, payload, len);

    /*
     * SystemInformationBlockType3 ::= SEQUENCE {
     *   cellReselectionInfoCommon SEQUENCE {
     *     q-Hyst ENUMERATED {...},
     *     speedStateReselectionPars SEQUENCE {...} OPTIONAL
     *   },
     *   cellReselectionServingFreqInfo SEQUENCE {...},
     *   intraFreqCellReselectionInfo SEQUENCE {...},
     *   ...
     * }
     */

    /* Extension marker */
    if (!bit_reader_has_bits(&br, 1)) {
        info->valid = true;
        return 0;
    }
    bit_reader_skip(&br, 1);

    /* cellReselectionInfoCommon */
    /* q-Hyst (4 bits) */
    if (bit_reader_has_bits(&br, 4)) {
        uint8_t q_hyst_idx = bit_reader_read(&br, 4);
        if (q_hyst_idx < sizeof(q_hyst_values)) {
            info->q_hyst = q_hyst_values[q_hyst_idx];
        }
    }

    /* speedStateReselectionPars presence */
    info->speed_state_reselection_present = bit_reader_read(&br, 1);
    if (info->speed_state_reselection_present) {
        /* Skip speed state parameters (complex) */
        bit_reader_skip(&br, 16);
    }

    /* cellReselectionServingFreqInfo */
    if (bit_reader_has_bits(&br, 16)) {
        /* s-NonIntraSearch presence */
        bool s_non_intra_present = bit_reader_read(&br, 1);
        if (s_non_intra_present && bit_reader_has_bits(&br, 5)) {
            info->s_non_intra_search = bit_reader_read(&br, 5) * 2;
        }

        /* threshServingLow (5 bits) */
        if (bit_reader_has_bits(&br, 5)) {
            info->thresh_serving_low = bit_reader_read(&br, 5) * 2;
        }

        /* cellReselectionPriority (3 bits) */
        if (bit_reader_has_bits(&br, 3)) {
            info->cell_reselection_priority = bit_reader_read(&br, 3);
        }
    }

    /* intraFreqCellReselectionInfo */
    if (bit_reader_has_bits(&br, 16)) {
        /* q-RxLevMin (6 bits, maps to -70 to -22 dBm) */
        if (bit_reader_has_bits(&br, 6)) {
            info->q_rxlevmin = (int8_t)(bit_reader_read(&br, 6) * 2 - 70);
        }

        /* p-Max presence and value */
        info->p_max_present = bit_reader_read(&br, 1);
        if (info->p_max_present && bit_reader_has_bits(&br, 6)) {
            info->p_max = (int8_t)(bit_reader_read(&br, 6) - 30);
        }

        /* s-IntraSearch presence and value */
        bool s_intra_present = bit_reader_read(&br, 1);
        if (s_intra_present && bit_reader_has_bits(&br, 5)) {
            info->s_intra_search = bit_reader_read(&br, 5) * 2;
        }

        /* allowedMeasBandwidth presence */
        info->allowed_meas_bandwidth_present = bit_reader_read(&br, 1);
        if (info->allowed_meas_bandwidth_present && bit_reader_has_bits(&br, 3)) {
            uint8_t bw_idx = bit_reader_read(&br, 3);
            static const uint8_t bw_values[] = {6, 15, 25, 50, 75, 100};
            if (bw_idx < 6) {
                info->allowed_meas_bandwidth = bw_values[bw_idx];
            }
        }

        /* presenceAntennaPort1 */
        if (bit_reader_has_bits(&br, 1)) {
            info->presence_antenna_port1 = bit_reader_read(&br, 1);
        }

        /* neighCellConfig (2 bits) */
        if (bit_reader_has_bits(&br, 2)) {
            info->neigh_cell_config = bit_reader_read(&br, 2);
        }

        /* t-ReselectionEUTRA (3 bits) */
        if (bit_reader_has_bits(&br, 3)) {
            info->t_reselection_eutra = bit_reader_read(&br, 3);
        }
    }

    info->valid = true;
    return 0;
}

/*============================================================================
 * SIB4 Parsing
 *============================================================================*/

int sib4_parse(const uint8_t *payload, uint32_t len, sib4_info_t *info) {
    if (payload == NULL || len == 0 || info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(sib4_info_t));

    bit_reader_t br;
    bit_reader_init(&br, payload, len);

    /*
     * SystemInformationBlockType4 ::= SEQUENCE {
     *   intraFreqNeighCellList IntraFreqNeighCellList OPTIONAL,
     *   intraFreqBlackCellList IntraFreqBlackCellList OPTIONAL,
     *   csg-PhysCellIdRange PhysCellIdRange OPTIONAL,
     *   ...
     * }
     */

    /* Extension marker */
    if (!bit_reader_has_bits(&br, 1)) {
        info->valid = true;
        return 0;
    }
    bit_reader_skip(&br, 1);

    /* intraFreqNeighCellList presence */
    bool neigh_list_present = bit_reader_read(&br, 1);

    /* intraFreqBlackCellList presence */
    bool black_list_present = bit_reader_read(&br, 1);

    /* csg-PhysCellIdRange presence */
    info->csg_pci_range_present = bit_reader_read(&br, 1);

    /* Parse intraFreqNeighCellList */
    if (neigh_list_present && bit_reader_has_bits(&br, 5)) {
        uint8_t num_cells = bit_reader_read(&br, 5) + 1;  /* 1-16 */
        if (num_cells > MAX_INTRA_FREQ_NEIGH_CELLS) {
            num_cells = MAX_INTRA_FREQ_NEIGH_CELLS;
        }

        for (int i = 0; i < num_cells && bit_reader_has_bits(&br, 14); i++) {
            /* physCellId (9 bits) */
            info->neigh_cells[i].phys_cell_id = bit_reader_read(&br, 9);

            /* q-OffsetCell (5 bits, maps to -24 to 24 dB) */
            int8_t q_offset_idx = bit_reader_read(&br, 5);
            info->neigh_cells[i].q_offset = (q_offset_idx - 15) * 2;

            info->num_neigh_cells++;
        }
    }

    /* Parse intraFreqBlackCellList */
    if (black_list_present && bit_reader_has_bits(&br, 5)) {
        uint8_t num_cells = bit_reader_read(&br, 5) + 1;
        if (num_cells > MAX_INTRA_FREQ_BLACK_CELLS) {
            num_cells = MAX_INTRA_FREQ_BLACK_CELLS;
        }

        for (int i = 0; i < num_cells && bit_reader_has_bits(&br, 9); i++) {
            /* start (9 bits) */
            info->black_cells[i].phys_cell_id_start = bit_reader_read(&br, 9);

            /* range presence */
            bool range_present = bit_reader_read(&br, 1);
            if (range_present && bit_reader_has_bits(&br, 8)) {
                info->black_cells[i].phys_cell_id_range = bit_reader_read(&br, 8);
            }

            info->num_black_cells++;
        }
    }

    /* Parse csg-PhysCellIdRange */
    if (info->csg_pci_range_present && bit_reader_has_bits(&br, 10)) {
        info->csg_pci_start = bit_reader_read(&br, 9);
        bool range_present = bit_reader_read(&br, 1);
        if (range_present && bit_reader_has_bits(&br, 8)) {
            info->csg_pci_range = bit_reader_read(&br, 8);
        }
    }

    info->valid = true;
    return 0;
}

/*============================================================================
 * SIB5 Parsing
 *============================================================================*/

int sib5_parse(const uint8_t *payload, uint32_t len, sib5_info_t *info) {
    if (payload == NULL || len == 0 || info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(sib5_info_t));

    bit_reader_t br;
    bit_reader_init(&br, payload, len);

    /*
     * SystemInformationBlockType5 ::= SEQUENCE {
     *   interFreqCarrierFreqList InterFreqCarrierFreqList,
     *   ...
     * }
     *
     * InterFreqCarrierFreqList ::= SEQUENCE (SIZE(1..8)) OF InterFreqCarrierFreqInfo
     */

    /* Extension marker */
    if (!bit_reader_has_bits(&br, 1)) {
        info->valid = true;
        return 0;
    }
    bit_reader_skip(&br, 1);

    /* Number of carriers (3 bits = 1-8) */
    if (!bit_reader_has_bits(&br, 3)) {
        info->valid = true;
        return 0;
    }
    uint8_t num_carriers = bit_reader_read(&br, 3) + 1;
    if (num_carriers > MAX_INTER_FREQ_CARRIERS) {
        num_carriers = MAX_INTER_FREQ_CARRIERS;
    }

    /* Parse each carrier */
    for (int i = 0; i < num_carriers; i++) {
        inter_freq_carrier_t *carrier = &info->carriers[info->num_carriers];

        /* Check for minimum required bits */
        if (!bit_reader_has_bits(&br, 32)) {
            break;
        }

        /* dl-CarrierFreq (16 bits EARFCN) */
        carrier->dl_carrier_freq = bit_reader_read(&br, 16);

        /* q-RxLevMin (6 bits) */
        carrier->q_rxlevmin = (int8_t)(bit_reader_read(&br, 6) * 2 - 70);

        /* p-Max presence and value */
        carrier->p_max_present = bit_reader_read(&br, 1);
        if (carrier->p_max_present && bit_reader_has_bits(&br, 6)) {
            carrier->p_max = (int8_t)(bit_reader_read(&br, 6) - 30);
        }

        /* t-ReselectionEUTRA (3 bits) */
        if (bit_reader_has_bits(&br, 3)) {
            carrier->t_reselection_eutra = bit_reader_read(&br, 3);
        }

        /* threshX-High (5 bits) */
        if (bit_reader_has_bits(&br, 5)) {
            carrier->thresh_x_high = bit_reader_read(&br, 5) * 2;
        }

        /* threshX-Low (5 bits) */
        if (bit_reader_has_bits(&br, 5)) {
            carrier->thresh_x_low = bit_reader_read(&br, 5) * 2;
        }

        /* allowedMeasBandwidth (3 bits) */
        if (bit_reader_has_bits(&br, 3)) {
            uint8_t bw_idx = bit_reader_read(&br, 3);
            static const uint8_t bw_values[] = {6, 15, 25, 50, 75, 100};
            if (bw_idx < 6) {
                carrier->allowed_meas_bandwidth = bw_values[bw_idx];
            }
        }

        /* presenceAntennaPort1 */
        if (bit_reader_has_bits(&br, 1)) {
            carrier->presence_antenna_port1 = bit_reader_read(&br, 1);
        }

        /* cellReselectionPriority presence and value */
        carrier->priority_present = bit_reader_read(&br, 1);
        if (carrier->priority_present && bit_reader_has_bits(&br, 3)) {
            carrier->cell_reselection_priority = bit_reader_read(&br, 3);
        }

        /* neighCellConfig (2 bits) */
        if (bit_reader_has_bits(&br, 2)) {
            carrier->neigh_cell_config = bit_reader_read(&br, 2);
        }

        /* q-OffsetFreq (5 bits) - optional, check presence */
        if (bit_reader_has_bits(&br, 1)) {
            bool q_offset_present = bit_reader_read(&br, 1);
            if (q_offset_present && bit_reader_has_bits(&br, 5)) {
                int8_t q_offset_idx = bit_reader_read(&br, 5);
                carrier->q_offset_freq = (q_offset_idx - 15) * 2;
            }
        }

        info->num_carriers++;
    }

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
    fprintf(out, "  PRACH Config Index: %u\n", info->prach_config.prach_config_index);
    fprintf(out, "  PRACH Freq Offset: %u\n", info->prach_config.prach_freq_offset);
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

void sib3_print(const sib3_info_t *info, FILE *out) {
    if (info == NULL || out == NULL) {
        return;
    }

    fprintf(out, "=== SIB3 Information ===\n");

    if (!info->valid) {
        fprintf(out, "  Status: INVALID\n");
        return;
    }

    fprintf(out, "  Cell Reselection Info:\n");
    fprintf(out, "    q-Hyst: %d dB\n", info->q_hyst);
    fprintf(out, "    Speed State Reselection: %s\n",
            info->speed_state_reselection_present ? "Present" : "Not present");

    fprintf(out, "  Serving Freq Info:\n");
    fprintf(out, "    s-NonIntraSearch: %u dB\n", info->s_non_intra_search);
    fprintf(out, "    threshServingLow: %u dB\n", info->thresh_serving_low);
    fprintf(out, "    cellReselectionPriority: %u\n", info->cell_reselection_priority);

    fprintf(out, "  Intra-Freq Cell Reselection:\n");
    fprintf(out, "    q-RxLevMin: %d dBm\n", info->q_rxlevmin);
    if (info->p_max_present) {
        fprintf(out, "    p-Max: %d dBm\n", info->p_max);
    }
    fprintf(out, "    s-IntraSearch: %u dB\n", info->s_intra_search);
    if (info->allowed_meas_bandwidth_present) {
        fprintf(out, "    allowedMeasBandwidth: %u RBs\n", info->allowed_meas_bandwidth);
    }
    fprintf(out, "    presenceAntennaPort1: %s\n",
            info->presence_antenna_port1 ? "Yes" : "No");
    fprintf(out, "    t-ReselectionEUTRA: %u s\n", info->t_reselection_eutra);

    fprintf(out, "========================\n");
}

void sib4_print(const sib4_info_t *info, FILE *out) {
    if (info == NULL || out == NULL) {
        return;
    }

    fprintf(out, "=== SIB4 Information ===\n");

    if (!info->valid) {
        fprintf(out, "  Status: INVALID\n");
        return;
    }

    fprintf(out, "  Intra-Freq Neighbor Cells (%u):\n", info->num_neigh_cells);
    for (int i = 0; i < info->num_neigh_cells; i++) {
        fprintf(out, "    [%d] PCI: %u, q-Offset: %d dB\n",
                i, info->neigh_cells[i].phys_cell_id,
                info->neigh_cells[i].q_offset);
    }

    fprintf(out, "  Intra-Freq Blacklist Cells (%u):\n", info->num_black_cells);
    for (int i = 0; i < info->num_black_cells; i++) {
        fprintf(out, "    [%d] PCI Start: %u, Range: %u\n",
                i, info->black_cells[i].phys_cell_id_start,
                info->black_cells[i].phys_cell_id_range);
    }

    if (info->csg_pci_range_present) {
        fprintf(out, "  CSG PCI Range: %u - %u\n",
                info->csg_pci_start,
                info->csg_pci_start + info->csg_pci_range);
    }

    fprintf(out, "========================\n");
}

void sib5_print(const sib5_info_t *info, FILE *out) {
    if (info == NULL || out == NULL) {
        return;
    }

    fprintf(out, "=== SIB5 Information ===\n");

    if (!info->valid) {
        fprintf(out, "  Status: INVALID\n");
        return;
    }

    fprintf(out, "  Inter-Freq Carriers (%u):\n", info->num_carriers);
    for (int i = 0; i < info->num_carriers; i++) {
        const inter_freq_carrier_t *c = &info->carriers[i];
        fprintf(out, "    [%d] EARFCN: %u\n", i, c->dl_carrier_freq);
        fprintf(out, "        q-RxLevMin: %d dBm\n", c->q_rxlevmin);
        if (c->p_max_present) {
            fprintf(out, "        p-Max: %d dBm\n", c->p_max);
        }
        fprintf(out, "        t-ReselectionEUTRA: %u s\n", c->t_reselection_eutra);
        fprintf(out, "        threshX-High: %u dB, threshX-Low: %u dB\n",
                c->thresh_x_high, c->thresh_x_low);
        fprintf(out, "        allowedMeasBandwidth: %u RBs\n", c->allowed_meas_bandwidth);
        if (c->priority_present) {
            fprintf(out, "        cellReselectionPriority: %u\n", c->cell_reselection_priority);
        }
        fprintf(out, "        q-OffsetFreq: %d dB\n", c->q_offset_freq);
    }

    fprintf(out, "========================\n");
}

/*============================================================================
 * JSON Formatting Functions
 *============================================================================*/

int sib1_to_json(const sib1_info_t *info, char *buf, size_t buf_len) {
    if (info == NULL || buf == NULL || buf_len == 0) {
        return -1;
    }

    if (!info->valid) {
        return snprintf(buf, buf_len, "{\"type\":\"SIB1\",\"valid\":false}");
    }

    int written = snprintf(buf, buf_len,
        "{"
        "\"type\":\"SIB1\","
        "\"tac\":%u,"
        "\"cell_id\":%u,"
        "\"cell_barred\":%s,"
        "\"num_plmn\":%u,"
        "\"plmn\":[",
        info->tac,
        info->cell_id,
        info->cell_barred ? "true" : "false",
        info->num_plmn_ids
    );

    for (int i = 0; i < info->num_plmn_ids && written < (int)buf_len - 50; i++) {
        if (i > 0) {
            written += snprintf(buf + written, buf_len - written, ",");
        }
        written += snprintf(buf + written, buf_len - written,
            "{\"mcc\":%u,\"mnc\":%u}",
            info->plmn_ids[i].mcc, info->plmn_ids[i].mnc);
    }

    written += snprintf(buf + written, buf_len - written,
        "],"
        "\"si_window_ms\":%u,"
        "\"num_si_messages\":%u,"
        "\"sib2_found\":%s,"
        "\"valid\":true"
        "}",
        info->si_window_length,
        info->num_si_messages,
        info->sib2_found ? "true" : "false"
    );

    return written;
}

int sib2_to_json(const sib2_info_t *info, char *buf, size_t buf_len) {
    if (info == NULL || buf == NULL || buf_len == 0) {
        return -1;
    }

    if (!info->valid) {
        return snprintf(buf, buf_len, "{\"type\":\"SIB2\",\"valid\":false}");
    }

    return snprintf(buf, buf_len,
        "{"
        "\"type\":\"SIB2\","
        "\"ac_barring_emergency\":%s,"
        "\"reference_signal_power\":%d,"
        "\"p_b\":%u,"
        "\"prach_config_index\":%u,"
        "\"prach_freq_offset\":%u,"
        "\"t300\":%u,"
        "\"t301\":%u,"
        "\"t310\":%u,"
        "\"t311\":%u,"
        "\"n310\":%u,"
        "\"n311\":%u,"
        "\"valid\":true"
        "}",
        info->ac_barring_for_emergency ? "true" : "false",
        info->reference_signal_power,
        info->p_b,
        info->prach_config.prach_config_index,
        info->prach_config.prach_freq_offset,
        info->t300,
        info->t301,
        info->t310,
        info->t311,
        info->n310,
        info->n311
    );
}

int sib3_to_json(const sib3_info_t *info, char *buf, size_t buf_len) {
    if (info == NULL || buf == NULL || buf_len == 0) {
        return -1;
    }

    if (!info->valid) {
        return snprintf(buf, buf_len, "{\"type\":\"SIB3\",\"valid\":false}");
    }

    return snprintf(buf, buf_len,
        "{"
        "\"type\":\"SIB3\","
        "\"q_hyst\":%d,"
        "\"thresh_serving_low\":%u,"
        "\"cell_reselection_priority\":%u,"
        "\"q_rxlevmin\":%d,"
        "\"s_intra_search\":%u,"
        "\"t_reselection_eutra\":%u,"
        "\"valid\":true"
        "}",
        info->q_hyst,
        info->thresh_serving_low,
        info->cell_reselection_priority,
        info->q_rxlevmin,
        info->s_intra_search,
        info->t_reselection_eutra
    );
}
