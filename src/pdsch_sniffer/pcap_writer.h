/*
 * pcap_writer.h — minimal pcapng writer used by the sniffer to emit
 * mac-lte-framed packets directly (no text2pcap round-trip).
 *
 * Header layout matches python/srslte_sniffer/pcap_io.py PcapngWriter so
 * captures are interchangeable across the C/Python halves of the project.
 */
#ifndef SNIFFER_PCAP_WRITER_H
#define SNIFFER_PCAP_WRITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SNIFFER_DLT_USER0 147

#define SNIFFER_PCCH 0
#define SNIFFER_SIB1 1
#define SNIFFER_SIB2 2

typedef struct {
    FILE*    fh;
    uint32_t link_type;
    uint32_t snaplen;
} sniffer_pcap_t;

int  sniffer_pcap_open(sniffer_pcap_t* w, const char* path);
void sniffer_pcap_close(sniffer_pcap_t* w);

/* Each writes the appropriate 15-byte mac-lte pseudo-header automatically. */
int  sniffer_pcap_write_pcch(sniffer_pcap_t* w,
                             const uint8_t* pdu, size_t len, uint64_t ts_us);
int  sniffer_pcap_write_sib1(sniffer_pcap_t* w,
                             const uint8_t* pdu, size_t len, uint64_t ts_us);
int  sniffer_pcap_write_sib2(sniffer_pcap_t* w,
                             const uint8_t* pdu, size_t len, uint64_t ts_us);

#endif /* SNIFFER_PCAP_WRITER_H */
