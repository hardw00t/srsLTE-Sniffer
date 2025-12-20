/**
 * pcap_writer.c - Direct PCAP file writing implementation
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "pcap_writer.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

/*============================================================================
 * PCAP File Header (Global)
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

/*============================================================================
 * PCAP Packet Header
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_rec_hdr_t;

/*============================================================================
 * GSMTAP Header
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint8_t  version;       /* GSMTAP version, must be 0x02 */
    uint8_t  hdr_len;       /* Header length in 4-byte words */
    uint8_t  type;          /* Protocol type */
    uint8_t  timeslot;      /* Timeslot or 0 */
    uint16_t arfcn;         /* ARFCN or 0 */
    int8_t   signal_dbm;    /* Signal level */
    int8_t   snr_db;        /* SNR */
    uint32_t frame_number;  /* Frame number */
    uint8_t  sub_type;      /* Protocol subtype */
    uint8_t  antenna_nr;    /* Antenna number */
    uint8_t  sub_slot;      /* Sub-slot */
    uint8_t  res;           /* Reserved */
} gsmtap_hdr_t;

/*============================================================================
 * Writer Structure
 *============================================================================*/

struct pcap_writer {
    FILE           *fp;
    pcap_config_t   config;
    pcap_stats_t    stats;
    bool            header_written;
};

/*============================================================================
 * Lifecycle
 *============================================================================*/

pcap_writer_t *pcap_writer_create(const pcap_config_t *config) {
    pcap_writer_t *writer = calloc(1, sizeof(pcap_writer_t));
    if (!writer) return NULL;

    /* Apply configuration */
    if (config) {
        memcpy(&writer->config, config, sizeof(pcap_config_t));
    } else {
        writer->config.filename = "capture.pcap";
        writer->config.snaplen = 65535;
        writer->config.flush_each = false;
    }

    if (writer->config.snaplen == 0) {
        writer->config.snaplen = 65535;
    }

    /* Open file */
    const char *mode = writer->config.append ? "ab" : "wb";
    writer->fp = fopen(writer->config.filename, mode);
    if (!writer->fp) {
        free(writer);
        return NULL;
    }

    /* Write global header if new file */
    if (!writer->config.append) {
        pcap_hdr_t hdr = {
            .magic_number = PCAP_MAGIC,
            .version_major = PCAP_VERSION_MAJOR,
            .version_minor = PCAP_VERSION_MINOR,
            .thiszone = 0,
            .sigfigs = 0,
            .snaplen = writer->config.snaplen,
            .network = PCAP_LINKTYPE_GSMTAP
        };

        if (fwrite(&hdr, sizeof(hdr), 1, writer->fp) != 1) {
            fclose(writer->fp);
            free(writer);
            return NULL;
        }

        writer->header_written = true;
    }

    return writer;
}

void pcap_writer_destroy(pcap_writer_t *writer) {
    if (!writer) return;

    if (writer->fp) {
        fflush(writer->fp);
        fclose(writer->fp);
    }

    free(writer);
}

void pcap_writer_flush(pcap_writer_t *writer) {
    if (writer && writer->fp) {
        fflush(writer->fp);
    }
}

/*============================================================================
 * Writing Functions
 *============================================================================*/

int pcap_write_packet(pcap_writer_t *writer,
                       const uint8_t *data,
                       uint32_t len,
                       uint32_t tv_sec,
                       uint32_t tv_usec) {
    if (!writer || !writer->fp || !data || len == 0) {
        return -1;
    }

    /* Truncate if necessary */
    uint32_t incl_len = (len > writer->config.snaplen) ?
                        writer->config.snaplen : len;

    /* Write packet header */
    pcap_rec_hdr_t rec_hdr = {
        .ts_sec = tv_sec,
        .ts_usec = tv_usec,
        .incl_len = incl_len,
        .orig_len = len
    };

    if (fwrite(&rec_hdr, sizeof(rec_hdr), 1, writer->fp) != 1) {
        writer->stats.errors++;
        return -1;
    }

    /* Write packet data */
    if (fwrite(data, 1, incl_len, writer->fp) != incl_len) {
        writer->stats.errors++;
        return -1;
    }

    writer->stats.packets_written++;
    writer->stats.bytes_written += incl_len;

    if (writer->config.flush_each) {
        fflush(writer->fp);
    }

    return 0;
}

int pcap_write_lte_rrc(pcap_writer_t *writer,
                        gsmtap_lte_rrc_subtype_t subtype,
                        const uint8_t *data,
                        uint32_t len,
                        uint16_t sfn,
                        uint8_t sfidx,
                        uint16_t rnti) {
    if (!writer || !data || len == 0) {
        return -1;
    }

    /* Build GSMTAP header */
    gsmtap_hdr_t gsmtap = {
        .version = 0x02,
        .hdr_len = sizeof(gsmtap_hdr_t) / 4,
        .type = GSMTAP_TYPE_LTE_RRC,
        .timeslot = 0,
        .arfcn = htons(0),
        .signal_dbm = 0,
        .snr_db = 0,
        .frame_number = htonl((sfn << 4) | sfidx),
        .sub_type = subtype,
        .antenna_nr = 0,
        .sub_slot = 0,
        .res = 0
    };

    /* Allocate buffer for GSMTAP + payload */
    size_t total_len = sizeof(gsmtap_hdr_t) + len;
    uint8_t *buffer = malloc(total_len);
    if (!buffer) {
        return -1;
    }

    memcpy(buffer, &gsmtap, sizeof(gsmtap_hdr_t));
    memcpy(buffer + sizeof(gsmtap_hdr_t), data, len);

    /* Get current time */
    struct timeval tv;
    gettimeofday(&tv, NULL);

    int ret = pcap_write_packet(writer, buffer, total_len,
                                 (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec);

    free(buffer);
    return ret;
}

int pcap_write_paging(pcap_writer_t *writer,
                       const uint8_t *data,
                       uint32_t len,
                       uint16_t sfn,
                       uint8_t sfidx) {
    return pcap_write_lte_rrc(writer, GSMTAP_LTE_RRC_SUB_PCCH,
                               data, len, sfn, sfidx, 0xFFFF);
}

int pcap_write_sib1(pcap_writer_t *writer,
                     const uint8_t *data,
                     uint32_t len,
                     uint16_t sfn) {
    return pcap_write_lte_rrc(writer, GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH,
                               data, len, sfn, 5, 0xFFFF);
}

int pcap_write_sib2(pcap_writer_t *writer,
                     const uint8_t *data,
                     uint32_t len,
                     uint16_t sfn) {
    return pcap_write_lte_rrc(writer, GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH,
                               data, len, sfn, 0, 0xFFFF);
}

int pcap_write_mib(pcap_writer_t *writer,
                    const uint8_t *data,
                    uint32_t len,
                    uint16_t sfn) {
    return pcap_write_lte_rrc(writer, GSMTAP_LTE_RRC_SUB_BCCH_BCH,
                               data, len, sfn, 0, 0xFFFF);
}

/*============================================================================
 * Statistics
 *============================================================================*/

void pcap_writer_get_stats(pcap_writer_t *writer, pcap_stats_t *stats) {
    if (writer && stats) {
        memcpy(stats, &writer->stats, sizeof(pcap_stats_t));
    }
}

void pcap_writer_print_stats(pcap_writer_t *writer, FILE *out) {
    if (!writer || !out) return;

    fprintf(out, "\n=== PCAP Writer Statistics ===\n");
    fprintf(out, "File:    %s\n", writer->config.filename);
    fprintf(out, "Packets: %lu\n", (unsigned long)writer->stats.packets_written);
    fprintf(out, "Bytes:   %lu\n", (unsigned long)writer->stats.bytes_written);
    fprintf(out, "Errors:  %lu\n", (unsigned long)writer->stats.errors);
    fprintf(out, "==============================\n\n");
}
