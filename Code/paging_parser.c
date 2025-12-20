/**
 * paging_parser.c - LTE Paging Message parsing implementation
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "paging_parser.h"
#include "sib_parser.h"  /* For bit_reader */
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/*============================================================================
 * String Tables
 *============================================================================*/

static const char *paging_cause_strings[] = {
    "Unspecified",
    "Voice Call",
    "Video Call",
    "SMS",
    "MPS",
    "MCS",
    "Delay Tolerant"
};

static const char *paging_id_type_strings[] = {
    "S-TMSI",
    "IMSI"
};

/*============================================================================
 * Helper Functions
 *============================================================================*/

static bool is_valid_mcc(uint16_t mcc) {
    return mcc >= 100 && mcc <= 999;
}

static bool is_valid_mnc(uint16_t mnc) {
    return mnc >= 0 && mnc <= 999;
}

static bool is_digit_char(char c) {
    return c >= '0' && c <= '9';
}

static bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

/*============================================================================
 * S-TMSI Functions
 *============================================================================*/

void paging_stmsi_to_hex(const stmsi_t *stmsi, char *buf) {
    if (stmsi == NULL || buf == NULL) {
        return;
    }
    snprintf(buf, STMSI_HEX_LEN + 1, "%02x%08x", stmsi->mmec, stmsi->m_tmsi);
}

int paging_stmsi_from_hex(const char *hex, stmsi_t *stmsi) {
    if (hex == NULL || stmsi == NULL || strlen(hex) != STMSI_HEX_LEN) {
        return -1;
    }

    /* Verify all hex characters */
    for (int i = 0; i < STMSI_HEX_LEN; i++) {
        if (!is_hex_char(hex[i])) {
            return -1;
        }
    }

    /* Parse MMEC (first 2 hex chars = 8 bits) */
    char mmec_str[3] = {hex[0], hex[1], 0};
    stmsi->mmec = (uint8_t)strtoul(mmec_str, NULL, 16);

    /* Parse M-TMSI (last 8 hex chars = 32 bits) */
    char mtmsi_str[9];
    strncpy(mtmsi_str, hex + 2, 8);
    mtmsi_str[8] = 0;
    stmsi->m_tmsi = (uint32_t)strtoul(mtmsi_str, NULL, 16);

    /* Store hex string */
    strncpy(stmsi->hex_str, hex, STMSI_HEX_LEN);
    stmsi->hex_str[STMSI_HEX_LEN] = 0;

    /* Convert to lowercase */
    for (int i = 0; i < STMSI_HEX_LEN; i++) {
        stmsi->hex_str[i] = tolower(stmsi->hex_str[i]);
    }

    return 0;
}

int paging_parse_stmsi(const uint8_t *data, stmsi_t *stmsi) {
    if (data == NULL || stmsi == NULL) {
        return -1;
    }

    memset(stmsi, 0, sizeof(stmsi_t));

    /* S-TMSI is 40 bits (5 bytes):
     *   - MMEC: 8 bits
     *   - M-TMSI: 32 bits
     */
    stmsi->mmec = data[0];
    stmsi->m_tmsi = ((uint32_t)data[1] << 24) |
                    ((uint32_t)data[2] << 16) |
                    ((uint32_t)data[3] << 8) |
                    (uint32_t)data[4];

    paging_stmsi_to_hex(stmsi, stmsi->hex_str);
    return 0;
}

/*============================================================================
 * IMSI Functions
 *============================================================================*/

int paging_parse_imsi(const uint8_t *data, uint32_t len, imsi_t *imsi) {
    if (data == NULL || len == 0 || imsi == NULL) {
        return -1;
    }

    memset(imsi, 0, sizeof(imsi_t));

    /*
     * IMSI encoding (3GPP TS 24.008):
     *
     * For odd-length IMSI (15 digits):
     *   Byte 0: [Digit 1] [Type of identity (4 bits)]
     *   Byte 1: [Digit 3] [Digit 2]
     *   ...
     *   Byte 7: [Digit 15] [Digit 14]
     *
     * For even-length IMSI (14 digits):
     *   Byte 0: [1111] [Type of identity (4 bits)]
     *   Byte 1: [Digit 2] [Digit 1]
     *   ...
     */

    int idx = 0;

    /* First nibble might contain first digit (odd length) or 0xF (even) */
    uint8_t first_nibble = (data[0] >> 4) & 0x0F;
    if (first_nibble != 0x0F && first_nibble <= 9) {
        imsi->digits[idx++] = '0' + first_nibble;
    }

    /* Process remaining bytes */
    for (uint32_t i = 1; i < len && idx < IMSI_MAX_DIGITS; i++) {
        uint8_t low = data[i] & 0x0F;
        uint8_t high = (data[i] >> 4) & 0x0F;

        if (low <= 9) {
            imsi->digits[idx++] = '0' + low;
        }
        if (high <= 9 && high != 0x0F && idx < IMSI_MAX_DIGITS) {
            imsi->digits[idx++] = '0' + high;
        }
    }

    imsi->digits[idx] = '\0';
    imsi->length = idx;

    /* Extract MCC/MNC */
    if (imsi->length >= 5) {
        imsi->mcc = (imsi->digits[0] - '0') * 100 +
                    (imsi->digits[1] - '0') * 10 +
                    (imsi->digits[2] - '0');

        /* Check if MNC is 3 digits based on MCC */
        /* Common 3-digit MNC countries: USA (310-316), Canada (302), etc. */
        if (imsi->mcc >= 310 && imsi->mcc <= 316) {
            imsi->mnc_3_digits = true;
            imsi->mnc = (imsi->digits[3] - '0') * 100 +
                        (imsi->digits[4] - '0') * 10 +
                        (imsi->digits[5] - '0');
        } else {
            imsi->mnc_3_digits = false;
            imsi->mnc = (imsi->digits[3] - '0') * 10 +
                        (imsi->digits[4] - '0');
        }
    }

    return (imsi->length >= 14) ? 0 : -1;
}

void paging_extract_plmn(const imsi_t *imsi, uint16_t *mcc, uint16_t *mnc) {
    if (imsi == NULL || mcc == NULL || mnc == NULL) {
        return;
    }
    *mcc = imsi->mcc;
    *mnc = imsi->mnc;
}

/*============================================================================
 * Heuristic Parsing
 *============================================================================*/

int paging_find_imsi_heuristic(const uint8_t *payload, uint32_t len, imsi_t *imsi) {
    if (payload == NULL || len < 8 || imsi == NULL) {
        return -1;
    }

    memset(imsi, 0, sizeof(imsi_t));

    /*
     * Heuristic approach:
     * Look for patterns that indicate IMSI:
     * 1. Look for "9" followed by MCC/MNC pattern
     * 2. IMSI starts with valid MCC (3 digits, typically 2xx-9xx)
     * 3. Followed by 12-13 more digits
     * 4. Often ends with specific delimiter byte (0x08)
     */

    /* Convert payload to hex string for pattern matching */
    char hex_buf[1024];
    int hex_len = 0;

    for (uint32_t i = 0; i < len && hex_len < (int)sizeof(hex_buf) - 2; i++) {
        hex_len += snprintf(hex_buf + hex_len, sizeof(hex_buf) - hex_len,
                            "%02x", payload[i]);
    }

    /* Search for IMSI pattern: "9" followed by 15 digits ending with "8" */
    for (int i = 0; i < hex_len - 17; i++) {
        if (hex_buf[i] == '9') {
            /* Check if next 15 chars are digits */
            bool all_digits = true;
            for (int j = 1; j <= 15 && all_digits; j++) {
                if (!is_digit_char(hex_buf[i + j])) {
                    all_digits = false;
                }
            }

            /* Check for trailing '8' delimiter */
            if (all_digits && (i + 16 < hex_len) && hex_buf[i + 16] == '8') {
                /* Extract MCC from position i+1 to i+3 */
                int mcc = (hex_buf[i + 1] - '0') * 100 +
                          (hex_buf[i + 2] - '0') * 10 +
                          (hex_buf[i + 3] - '0');

                /* Validate MCC range */
                if (is_valid_mcc(mcc)) {
                    /* Check MNC is not "00" (invalid) */
                    int mnc = (hex_buf[i + 4] - '0') * 10 +
                              (hex_buf[i + 5] - '0');

                    if (mnc > 0) {
                        /* Found valid IMSI pattern */
                        strncpy(imsi->digits, hex_buf + i + 1, 15);
                        imsi->digits[15] = '\0';
                        imsi->length = 15;
                        imsi->mcc = mcc;
                        imsi->mnc = mnc;
                        return 0;
                    }
                }
            }

            /* Also try 14-digit IMSI */
            if (all_digits && (i + 15 < hex_len) && hex_buf[i + 15] == '8') {
                int mcc = (hex_buf[i + 1] - '0') * 100 +
                          (hex_buf[i + 2] - '0') * 10 +
                          (hex_buf[i + 3] - '0');

                if (is_valid_mcc(mcc)) {
                    strncpy(imsi->digits, hex_buf + i + 1, 14);
                    imsi->digits[14] = '\0';
                    imsi->length = 14;
                    imsi->mcc = mcc;
                    imsi->mnc = (hex_buf[i + 4] - '0') * 10 +
                                (hex_buf[i + 5] - '0');
                    return 0;
                }
            }
        }
    }

    return -1;
}

int paging_find_stmsi_heuristic(const uint8_t *payload, uint32_t len, stmsi_t *stmsi) {
    if (payload == NULL || len < 5 || stmsi == NULL) {
        return -1;
    }

    memset(stmsi, 0, sizeof(stmsi_t));

    /*
     * Heuristic approach for S-TMSI:
     * S-TMSI is 40 bits (5 bytes) with:
     *   - MMEC: 8 bits (usually non-zero)
     *   - M-TMSI: 32 bits (random-looking, contains hex letters)
     *
     * Pattern: Look for 10 hex characters that contain at least
     * one letter (a-f) to distinguish from digit-only IMSI fragments
     */

    /* Convert to hex string */
    char hex_buf[1024];
    int hex_len = 0;

    for (uint32_t i = 0; i < len && hex_len < (int)sizeof(hex_buf) - 2; i++) {
        hex_len += snprintf(hex_buf + hex_len, sizeof(hex_buf) - hex_len,
                            "%02x", payload[i]);
    }

    /* Search for 10-char hex sequence with at least one letter */
    for (int i = 0; i < hex_len - 10; i++) {
        bool all_hex = true;
        bool has_letter = false;

        for (int j = 0; j < 10 && all_hex; j++) {
            char c = hex_buf[i + j];
            if (!is_hex_char(c)) {
                all_hex = false;
            } else if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                has_letter = true;
            }
        }

        if (all_hex && has_letter) {
            /* Found potential S-TMSI */
            char stmsi_hex[11];
            strncpy(stmsi_hex, hex_buf + i, 10);
            stmsi_hex[10] = '\0';

            if (paging_stmsi_from_hex(stmsi_hex, stmsi) == 0) {
                return 0;
            }
        }
    }

    return -1;
}

/*============================================================================
 * Paging Message Parsing
 *============================================================================*/

int paging_parse(const uint8_t *payload, uint32_t len, paging_message_t *msg) {
    return paging_parse_with_context(payload, len, 0, 0, 0, msg);
}

int paging_parse_with_context(const uint8_t *payload, uint32_t len,
                              uint32_t sfn, uint8_t subframe, uint16_t cell_id,
                              paging_message_t *msg) {
    if (payload == NULL || len == 0 || msg == NULL) {
        return -1;
    }

    memset(msg, 0, sizeof(paging_message_t));
    msg->sfn = sfn;
    msg->subframe = subframe;
    msg->cell_id = cell_id;

    /*
     * Paging message ASN.1 structure (3GPP TS 36.331):
     *
     * PCCH-Message ::= SEQUENCE {
     *   message PCCH-MessageType
     * }
     *
     * PCCH-MessageType ::= CHOICE {
     *   c1 CHOICE {
     *     paging Paging
     *   },
     *   ...
     * }
     *
     * Paging ::= SEQUENCE {
     *   pagingRecordList PagingRecordList OPTIONAL,
     *   systemInfoModification ENUMERATED {true} OPTIONAL,
     *   etws-Indication ENUMERATED {true} OPTIONAL,
     *   nonCriticalExtension SEQUENCE {...} OPTIONAL
     * }
     *
     * PagingRecordList ::= SEQUENCE (SIZE(1..16)) OF PagingRecord
     *
     * PagingRecord ::= SEQUENCE {
     *   ue-Identity PagingUE-Identity,
     *   cn-Domain ENUMERATED {ps, cs},
     *   ...
     * }
     *
     * PagingUE-Identity ::= CHOICE {
     *   s-TMSI S-TMSI,
     *   imsi IMSI
     * }
     */

    bit_reader_t br;
    bit_reader_init(&br, payload, len);

    /* Skip PCCH message type indicator */
    if (!bit_reader_has_bits(&br, 2)) {
        goto heuristic;
    }
    bit_reader_skip(&br, 1);  /* Extension marker */

    /* Check for paging record list presence */
    bool has_records = bit_reader_read(&br, 1);

    /* System info modification */
    msg->si_modification = bit_reader_read(&br, 1);

    /* ETWS indication */
    msg->etws_indication = bit_reader_read(&br, 1);

    if (!has_records) {
        /* No paging records, but message is valid */
        msg->valid = true;
        return 0;
    }

    /* Parse paging record list */
    if (!bit_reader_has_bits(&br, 4)) {
        goto heuristic;
    }

    uint8_t num_records = bit_reader_read(&br, 4) + 1;  /* 1-16 */
    if (num_records > MAX_PAGING_RECORDS) {
        num_records = MAX_PAGING_RECORDS;
    }

    for (int i = 0; i < num_records && bit_reader_has_bits(&br, 8); i++) {
        paging_record_t *rec = &msg->records[msg->num_records];

        /* Extension marker for PagingRecord */
        bit_reader_read(&br, 1);

        /* ue-Identity choice (1 bit): 0=S-TMSI, 1=IMSI */
        rec->id_type = bit_reader_read(&br, 1) ? PAGING_ID_IMSI : PAGING_ID_STMSI;

        if (rec->id_type == PAGING_ID_STMSI) {
            /* S-TMSI: 40 bits */
            if (!bit_reader_has_bits(&br, 40)) {
                break;
            }

            uint8_t stmsi_data[5];
            for (int j = 0; j < 5; j++) {
                stmsi_data[j] = bit_reader_read(&br, 8);
            }
            paging_parse_stmsi(stmsi_data, &rec->stmsi);
            msg->num_stmsi++;

        } else {
            /* IMSI: variable length (6-8 bytes typical) */
            if (!bit_reader_has_bits(&br, 4)) {
                break;
            }

            uint8_t imsi_len = bit_reader_read(&br, 4) + 6;  /* 6-21 digits */
            if (imsi_len > 21) imsi_len = 21;

            uint8_t imsi_bytes = (imsi_len + 1) / 2;
            if (!bit_reader_has_bits(&br, imsi_bytes * 8)) {
                break;
            }

            uint8_t imsi_data[11];
            for (int j = 0; j < imsi_bytes && j < 11; j++) {
                imsi_data[j] = bit_reader_read(&br, 8);
            }
            paging_parse_imsi(imsi_data, imsi_bytes, &rec->imsi);
            msg->num_imsi++;
        }

        /* CN domain (1 bit) */
        rec->cn_domain = bit_reader_read(&br, 1);
        rec->cn_domain_present = true;

        msg->num_records++;
    }

    msg->valid = true;
    return 0;

heuristic:
    /*
     * Fallback: Use heuristic parsing when ASN.1 structure
     * is corrupted, truncated, or non-standard
     */
    msg->num_records = 0;

    /* Try to find IMSI */
    imsi_t found_imsi;
    if (paging_find_imsi_heuristic(payload, len, &found_imsi) == 0) {
        paging_record_t *rec = &msg->records[msg->num_records];
        rec->id_type = PAGING_ID_IMSI;
        memcpy(&rec->imsi, &found_imsi, sizeof(imsi_t));
        msg->num_records++;
        msg->num_imsi++;
    }

    /* Try to find S-TMSI */
    stmsi_t found_stmsi;
    if (paging_find_stmsi_heuristic(payload, len, &found_stmsi) == 0) {
        paging_record_t *rec = &msg->records[msg->num_records];
        rec->id_type = PAGING_ID_STMSI;
        memcpy(&rec->stmsi, &found_stmsi, sizeof(stmsi_t));
        msg->num_records++;
        msg->num_stmsi++;
    }

    msg->valid = (msg->num_records > 0);
    if (!msg->valid) {
        strncpy(msg->error_msg, "No identities found", sizeof(msg->error_msg) - 1);
    }

    return msg->valid ? 0 : -1;
}

/*============================================================================
 * String Functions
 *============================================================================*/

const char *paging_cause_str(paging_cause_t cause) {
    if (cause > PAGING_CAUSE_DELAY_TOLERANT) {
        return "Unknown";
    }
    return paging_cause_strings[cause];
}

const char *paging_id_type_str(paging_id_type_t type) {
    if (type > PAGING_ID_IMSI) {
        return "Unknown";
    }
    return paging_id_type_strings[type];
}

/*============================================================================
 * Debug/Print Functions
 *============================================================================*/

void paging_record_print(const paging_record_t *rec, int index, FILE *out) {
    if (rec == NULL || out == NULL) {
        return;
    }

    fprintf(out, "  Record %d:\n", index);
    fprintf(out, "    Type: %s\n", paging_id_type_str(rec->id_type));

    if (rec->id_type == PAGING_ID_IMSI) {
        fprintf(out, "    IMSI: %s\n", rec->imsi.digits);
        fprintf(out, "      MCC: %03u, MNC: %0*u\n",
                rec->imsi.mcc,
                rec->imsi.mnc_3_digits ? 3 : 2,
                rec->imsi.mnc);
    } else {
        fprintf(out, "    S-TMSI: %s\n", rec->stmsi.hex_str);
        fprintf(out, "      MMEC: 0x%02X, M-TMSI: 0x%08X\n",
                rec->stmsi.mmec, rec->stmsi.m_tmsi);
    }

    if (rec->cn_domain_present) {
        fprintf(out, "    CN Domain: %s\n", rec->cn_domain ? "CS" : "PS");
    }

    if (rec->paging_cause_present) {
        fprintf(out, "    Cause: %s\n", paging_cause_str(rec->paging_cause));
    }
}

void paging_print(const paging_message_t *msg, FILE *out) {
    if (msg == NULL || out == NULL) {
        return;
    }

    fprintf(out, "=== Paging Message ===\n");

    if (!msg->valid) {
        fprintf(out, "  Status: INVALID\n");
        if (msg->error_msg[0]) {
            fprintf(out, "  Error: %s\n", msg->error_msg);
        }
        return;
    }

    fprintf(out, "  SFN: %u, Subframe: %u\n", msg->sfn, msg->subframe);
    fprintf(out, "  Cell ID: %u\n", msg->cell_id);
    fprintf(out, "  Records: %u (IMSI: %u, S-TMSI: %u)\n",
            msg->num_records, msg->num_imsi, msg->num_stmsi);

    if (msg->si_modification) {
        fprintf(out, "  System Info Modified: Yes\n");
    }
    if (msg->etws_indication) {
        fprintf(out, "  ETWS Indication: Yes\n");
    }
    if (msg->cmas_indication) {
        fprintf(out, "  CMAS Indication: Yes\n");
    }

    for (int i = 0; i < msg->num_records; i++) {
        paging_record_print(&msg->records[i], i, out);
    }

    fprintf(out, "======================\n");
}

int paging_to_json(const paging_message_t *msg, char *buf, size_t buf_len) {
    if (msg == NULL || buf == NULL || buf_len == 0) {
        return -1;
    }

    if (!msg->valid) {
        return snprintf(buf, buf_len, "{\"type\":\"PAGING\",\"valid\":false}");
    }

    int written = snprintf(buf, buf_len,
        "{"
        "\"type\":\"PAGING\","
        "\"sfn\":%u,"
        "\"subframe\":%u,"
        "\"cell_id\":%u,"
        "\"num_records\":%u,"
        "\"num_imsi\":%u,"
        "\"num_stmsi\":%u,"
        "\"si_modification\":%s,"
        "\"etws\":%s,"
        "\"records\":[",
        msg->sfn,
        msg->subframe,
        msg->cell_id,
        msg->num_records,
        msg->num_imsi,
        msg->num_stmsi,
        msg->si_modification ? "true" : "false",
        msg->etws_indication ? "true" : "false"
    );

    /* Add records */
    for (int i = 0; i < msg->num_records && written < (int)buf_len - 100; i++) {
        const paging_record_t *rec = &msg->records[i];

        if (i > 0) {
            written += snprintf(buf + written, buf_len - written, ",");
        }

        if (rec->id_type == PAGING_ID_IMSI) {
            written += snprintf(buf + written, buf_len - written,
                "{\"type\":\"IMSI\",\"value\":\"%s\",\"mcc\":%u,\"mnc\":%u}",
                rec->imsi.digits, rec->imsi.mcc, rec->imsi.mnc);
        } else {
            written += snprintf(buf + written, buf_len - written,
                "{\"type\":\"S-TMSI\",\"value\":\"%s\",\"mmec\":%u,\"m_tmsi\":%u}",
                rec->stmsi.hex_str, rec->stmsi.mmec, rec->stmsi.m_tmsi);
        }
    }

    written += snprintf(buf + written, buf_len - written, "],\"valid\":true}");

    return written;
}
