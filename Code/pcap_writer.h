/**
 * pcap_writer.h - Direct PCAP file writing with GSMTAP encapsulation
 *
 * Writes PCAP files directly without needing text2pcap.
 * Supports proper GSMTAP headers for LTE RRC messages.
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * GSMTAP Types (for Wireshark LTE dissection)
 *============================================================================*/

/* GSMTAP header type for LTE */
#define GSMTAP_TYPE_LTE_RRC     13

/* LTE RRC subtypes */
typedef enum {
    GSMTAP_LTE_RRC_SUB_DL_CCCH           = 0,
    GSMTAP_LTE_RRC_SUB_DL_DCCH           = 1,
    GSMTAP_LTE_RRC_SUB_UL_CCCH           = 2,
    GSMTAP_LTE_RRC_SUB_UL_DCCH           = 3,
    GSMTAP_LTE_RRC_SUB_BCCH_BCH          = 4,
    GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH       = 5,
    GSMTAP_LTE_RRC_SUB_PCCH              = 6,
    GSMTAP_LTE_RRC_SUB_MCCH              = 7,
    GSMTAP_LTE_RRC_SUB_BCCH_BCH_MBMS     = 8,
    GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_BR    = 9,
    GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_MBMS  = 10,
    GSMTAP_LTE_RRC_SUB_SC_MCCH           = 11,
    GSMTAP_LTE_RRC_SUB_SBCCH_SL_BCH      = 12,
    GSMTAP_LTE_RRC_SUB_SBCCH_SL_BCH_V2X  = 13,
    GSMTAP_LTE_RRC_SUB_DL_CCCH_NB        = 14,
    GSMTAP_LTE_RRC_SUB_DL_DCCH_NB        = 15,
    GSMTAP_LTE_RRC_SUB_UL_CCCH_NB        = 16,
    GSMTAP_LTE_RRC_SUB_UL_DCCH_NB        = 17,
    GSMTAP_LTE_RRC_SUB_BCCH_BCH_NB       = 18,
    GSMTAP_LTE_RRC_SUB_BCCH_BCH_TDD_NB   = 19,
    GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_NB    = 20,
    GSMTAP_LTE_RRC_SUB_PCCH_NB           = 21,
    GSMTAP_LTE_RRC_SUB_SC_MCCH_NB        = 22
} gsmtap_lte_rrc_subtype_t;

/*============================================================================
 * PCAP File Format Constants
 *============================================================================*/

#define PCAP_MAGIC          0xa1b2c3d4
#define PCAP_VERSION_MAJOR  2
#define PCAP_VERSION_MINOR  4
#define PCAP_LINKTYPE_GSMTAP 147  /* DLT_GSMTAP */

/*============================================================================
 * PCAP Writer Handle
 *============================================================================*/

typedef struct pcap_writer pcap_writer_t;

/*============================================================================
 * Configuration
 *============================================================================*/

typedef struct {
    const char *filename;
    bool        append;          /* Append to existing file */
    uint32_t    snaplen;         /* Max packet size (default 65535) */
    bool        flush_each;      /* Flush after each packet */
} pcap_config_t;

/*============================================================================
 * Lifecycle
 *============================================================================*/

/**
 * Create PCAP writer
 * @param config    Configuration (NULL for defaults)
 * @return          Writer handle or NULL
 */
pcap_writer_t *pcap_writer_create(const pcap_config_t *config);

/**
 * Destroy writer and close file
 */
void pcap_writer_destroy(pcap_writer_t *writer);

/**
 * Flush pending writes
 */
void pcap_writer_flush(pcap_writer_t *writer);

/*============================================================================
 * Writing Functions
 *============================================================================*/

/**
 * Write raw packet with custom timestamp
 * @param writer    Writer handle
 * @param data      Packet data
 * @param len       Packet length
 * @param tv_sec    Timestamp seconds
 * @param tv_usec   Timestamp microseconds
 * @return          0 on success, -1 on error
 */
int pcap_write_packet(pcap_writer_t *writer,
                       const uint8_t *data,
                       uint32_t len,
                       uint32_t tv_sec,
                       uint32_t tv_usec);

/**
 * Write LTE RRC message with GSMTAP header
 * @param writer    Writer handle
 * @param subtype   RRC message subtype (paging, SIB, etc.)
 * @param data      RRC payload
 * @param len       Payload length
 * @param sfn       System Frame Number
 * @param sfidx     Subframe index
 * @param rnti      Radio Network Temporary Identifier
 * @return          0 on success, -1 on error
 */
int pcap_write_lte_rrc(pcap_writer_t *writer,
                        gsmtap_lte_rrc_subtype_t subtype,
                        const uint8_t *data,
                        uint32_t len,
                        uint16_t sfn,
                        uint8_t sfidx,
                        uint16_t rnti);

/**
 * Write paging message
 */
int pcap_write_paging(pcap_writer_t *writer,
                       const uint8_t *data,
                       uint32_t len,
                       uint16_t sfn,
                       uint8_t sfidx);

/**
 * Write SIB1 message
 */
int pcap_write_sib1(pcap_writer_t *writer,
                     const uint8_t *data,
                     uint32_t len,
                     uint16_t sfn);

/**
 * Write SIB2 message
 */
int pcap_write_sib2(pcap_writer_t *writer,
                     const uint8_t *data,
                     uint32_t len,
                     uint16_t sfn);

/**
 * Write MIB message
 */
int pcap_write_mib(pcap_writer_t *writer,
                    const uint8_t *data,
                    uint32_t len,
                    uint16_t sfn);

/*============================================================================
 * Statistics
 *============================================================================*/

typedef struct {
    uint64_t packets_written;
    uint64_t bytes_written;
    uint64_t errors;
} pcap_stats_t;

/**
 * Get writer statistics
 */
void pcap_writer_get_stats(pcap_writer_t *writer, pcap_stats_t *stats);

/**
 * Print statistics
 */
void pcap_writer_print_stats(pcap_writer_t *writer, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* PCAP_WRITER_H */
