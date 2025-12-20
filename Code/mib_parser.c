/**
 * mib_parser.c - LTE Master Information Block parsing implementation
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "mib_parser.h"
#include <string.h>
#include <math.h>

/*============================================================================
 * Lookup Tables
 *============================================================================*/

/* Bandwidth to MHz mapping (3GPP TS 36.101) */
static const float bw_to_mhz[] = {
    1.4f,   /* n6:   6 RBs,   1.4 MHz */
    3.0f,   /* n15:  15 RBs,  3 MHz */
    5.0f,   /* n25:  25 RBs,  5 MHz */
    10.0f,  /* n50:  50 RBs,  10 MHz */
    15.0f,  /* n75:  75 RBs,  15 MHz */
    20.0f   /* n100: 100 RBs, 20 MHz */
};

/* Bandwidth to number of RBs mapping */
static const uint8_t bw_to_nrb[] = {
    6, 15, 25, 50, 75, 100
};

/* PHICH Ng values (3GPP TS 36.211 Section 6.9) */
static const float phich_ng[] = {
    1.0f/6.0f,  /* oneSixth: Ng = 1/6 */
    0.5f,       /* half:     Ng = 1/2 */
    1.0f,       /* one:      Ng = 1 */
    2.0f        /* two:      Ng = 2 */
};

/* Bandwidth strings */
static const char *bw_strings[] = {
    "1.4 MHz (6 RBs)",
    "3 MHz (15 RBs)",
    "5 MHz (25 RBs)",
    "10 MHz (50 RBs)",
    "15 MHz (75 RBs)",
    "20 MHz (100 RBs)"
};

/* PHICH duration strings */
static const char *phich_duration_strings[] = {
    "Normal",
    "Extended"
};

/* PHICH resource strings */
static const char *phich_resource_strings[] = {
    "1/6",
    "1/2",
    "1",
    "2"
};

/*============================================================================
 * MIB Parsing Implementation
 *============================================================================*/

int mib_parse(const uint8_t *payload, mib_info_t *info) {
    return mib_parse_with_context(payload, 0, 0, 0, info);
}

int mib_parse_with_context(const uint8_t *payload, uint8_t sfn_offset,
                           uint8_t nof_ports, uint32_t pci, mib_info_t *info) {
    if (payload == NULL || info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(mib_info_t));

    /*
     * MIB is 24 bits (3 bytes), packed as follows (MSB first):
     *
     * Byte 0: [BW2 BW1 BW0 PHICH_D PHICH_R1 PHICH_R0 SFN7 SFN6]
     * Byte 1: [SFN5 SFN4 SFN3 SFN2 SFN1 SFN0 SPARE SPARE]
     * Byte 2: [SPARE x 8]
     *
     * Where:
     *   BW[2:0]       = dl-Bandwidth (3 bits)
     *   PHICH_D       = phich-Duration (1 bit)
     *   PHICH_R[1:0]  = phich-Resource (2 bits)
     *   SFN[7:0]      = systemFrameNumber (8 bits, upper bits of SFN)
     *   SPARE         = spare bits (10 bits total)
     */

    /* Extract dl-Bandwidth (3 bits) */
    uint8_t dl_bw = (payload[0] >> 5) & 0x07;
    if (dl_bw > DL_BANDWIDTH_100) {
        dl_bw = DL_BANDWIDTH_100;  /* Clamp to valid range */
    }
    info->dl_bandwidth = (dl_bandwidth_t)dl_bw;
    info->n_rb_dl = bw_to_nrb[dl_bw];
    info->bandwidth_mhz = bw_to_mhz[dl_bw];

    /* Extract PHICH configuration */
    info->phich_duration = (phich_duration_t)((payload[0] >> 4) & 0x01);
    info->phich_resource = (phich_resource_t)((payload[0] >> 2) & 0x03);
    info->phich_ng = phich_ng[info->phich_resource];

    /* Extract System Frame Number (8 MSB bits) */
    uint8_t sfn_high = ((payload[0] & 0x03) << 6) | ((payload[1] >> 2) & 0x3F);
    info->sfn = (sfn_high << 2) | (sfn_offset & 0x03);
    info->sfn_offset = sfn_offset;

    /* Store context */
    info->nof_ports = nof_ports;
    info->pci = pci;

    /* Calculate PHICH groups */
    info->nof_phich_groups = mib_calc_phich_groups(info->n_rb_dl, info->phich_ng);

    /* Extract spare bits for debugging */
    info->spare_bits = ((payload[1] & 0x03) << 8) | payload[2];

    info->valid = true;
    return 0;
}

uint8_t mib_calc_phich_groups(uint8_t n_rb_dl, float ng) {
    /*
     * Per 3GPP TS 36.211 Table 6.9-1:
     * N_PHICH_group = ceil(Ng * N_RB_DL / 8) for normal cyclic prefix
     *
     * For extended CP, the formula is different but rarely used.
     */
    float n_groups = ng * n_rb_dl / 8.0f;
    return (uint8_t)ceilf(n_groups);
}

/*============================================================================
 * Utility Functions
 *============================================================================*/

float mib_bandwidth_to_mhz(dl_bandwidth_t bw) {
    if (bw > DL_BANDWIDTH_100) {
        return 0.0f;
    }
    return bw_to_mhz[bw];
}

uint8_t mib_bandwidth_to_nrb(dl_bandwidth_t bw) {
    if (bw > DL_BANDWIDTH_100) {
        return 0;
    }
    return bw_to_nrb[bw];
}

float mib_phich_resource_to_ng(phich_resource_t res) {
    if (res > PHICH_RESOURCE_TWO) {
        return 0.0f;
    }
    return phich_ng[res];
}

const char *mib_bandwidth_str(dl_bandwidth_t bw) {
    if (bw > DL_BANDWIDTH_100) {
        return "Unknown";
    }
    return bw_strings[bw];
}

const char *mib_phich_duration_str(phich_duration_t dur) {
    if (dur > PHICH_DURATION_EXTENDED) {
        return "Unknown";
    }
    return phich_duration_strings[dur];
}

const char *mib_phich_resource_str(phich_resource_t res) {
    if (res > PHICH_RESOURCE_TWO) {
        return "Unknown";
    }
    return phich_resource_strings[res];
}

/*============================================================================
 * Debug/Print Functions
 *============================================================================*/

void mib_print(const mib_info_t *info, FILE *out) {
    if (info == NULL || out == NULL) {
        return;
    }

    fprintf(out, "=== Master Information Block (MIB) ===\n");

    if (!info->valid) {
        fprintf(out, "  Status: INVALID\n");
        return;
    }

    fprintf(out, "  Physical Cell ID: %u\n", info->pci);
    fprintf(out, "  System Frame Number: %u\n", info->sfn);
    fprintf(out, "  DL Bandwidth: %s\n", mib_bandwidth_str(info->dl_bandwidth));
    fprintf(out, "    - %u Resource Blocks\n", info->n_rb_dl);
    fprintf(out, "    - %.1f MHz\n", info->bandwidth_mhz);
    fprintf(out, "  PHICH Configuration:\n");
    fprintf(out, "    - Duration: %s\n", mib_phich_duration_str(info->phich_duration));
    fprintf(out, "    - Resource (Ng): %s\n", mib_phich_resource_str(info->phich_resource));
    fprintf(out, "    - PHICH Groups: %u\n", info->nof_phich_groups);
    if (info->nof_ports > 0) {
        fprintf(out, "  Antenna Ports: %u\n", info->nof_ports);
    }
    fprintf(out, "======================================\n");
}

int mib_to_json(const mib_info_t *info, char *buf, size_t buf_len) {
    if (info == NULL || buf == NULL || buf_len == 0) {
        return -1;
    }

    if (!info->valid) {
        return snprintf(buf, buf_len, "{\"valid\":false}");
    }

    return snprintf(buf, buf_len,
        "{"
        "\"type\":\"MIB\","
        "\"pci\":%u,"
        "\"sfn\":%u,"
        "\"dl_bandwidth\":%u,"
        "\"dl_bandwidth_mhz\":%.1f,"
        "\"n_rb_dl\":%u,"
        "\"phich_duration\":\"%s\","
        "\"phich_resource\":\"%s\","
        "\"phich_ng\":%.4f,"
        "\"nof_phich_groups\":%u,"
        "\"nof_ports\":%u,"
        "\"timestamp_us\":%lu,"
        "\"valid\":true"
        "}",
        info->pci,
        info->sfn,
        (unsigned)info->dl_bandwidth,
        info->bandwidth_mhz,
        info->n_rb_dl,
        mib_phich_duration_str(info->phich_duration),
        mib_phich_resource_str(info->phich_resource),
        info->phich_ng,
        info->nof_phich_groups,
        info->nof_ports,
        (unsigned long)info->timestamp_us
    );
}
