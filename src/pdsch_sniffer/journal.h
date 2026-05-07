/*
 * journal.h — append-only crash-safe capture journal (matches
 * python/srslte_sniffer/journal.py format byte-for-byte).
 *
 * Record layout:
 *   u32 magic 0x53524C53 ('SRLS')   little-endian
 *   u32 version = 1
 *   u8  kind       (1=PCCH, 2=SIB1, 3=SIB2, 9=other)
 *   u64 ts_us
 *   u32 payload_len
 *   payload bytes
 */
#ifndef SNIFFER_JOURNAL_H
#define SNIFFER_JOURNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SNIFFER_JOURNAL_MAGIC   0x53524C53u
#define SNIFFER_JOURNAL_VERSION 1u

#define SNIFFER_JOURNAL_PCCH  1
#define SNIFFER_JOURNAL_SIB1  2
#define SNIFFER_JOURNAL_SIB2  3
#define SNIFFER_JOURNAL_OTHER 9

typedef struct {
    FILE* fh;
} sniffer_journal_t;

int  sniffer_journal_open(sniffer_journal_t* j, const char* path);
void sniffer_journal_close(sniffer_journal_t* j);
int  sniffer_journal_write(sniffer_journal_t* j,
                           uint8_t kind,
                           uint64_t ts_us,
                           const uint8_t* payload,
                           uint32_t len);

#endif
