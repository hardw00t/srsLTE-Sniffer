/* clock_gettime + CLOCK_REALTIME require POSIX visibility under strict ISO. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "pcap_writer.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static const uint8_t PAGING_HEADER[15] = {
    0x01, 0x01, 0x01, 0x02, 0xff, 0xfe, 0x03, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x07, 0x01, 0x01,
};
static const uint8_t SIB1_HEADER[15] = {
    0x01, 0x01, 0x04, 0x02, 0xff, 0xff, 0x03, 0x00,
    0x00, 0x04, 0x09, 0x05, 0x07, 0x01, 0x01,
};
static const uint8_t SIB2_HEADER[15] = {
    0x01, 0x01, 0x04, 0x02, 0xff, 0xff, 0x03, 0x00,
    0x00, 0x04, 0x0a, 0x12, 0x07, 0x01, 0x01,
};

/* pcapng block types */
#define BT_SHB 0x0A0D0D0A
#define BT_IDB 0x00000001
#define BT_EPB 0x00000006
#define PCAPNG_BO 0x1A2B3C4D

static int write_block(FILE* fh, uint32_t bt,
                       const uint8_t* body, size_t blen)
{
    size_t   pad   = (4 - (blen % 4)) % 4;
    uint32_t total = (uint32_t)(12 + blen + pad);
    if (fwrite(&bt, 4, 1, fh) != 1) return -1;
    if (fwrite(&total, 4, 1, fh) != 1) return -1;
    if (blen && fwrite(body, 1, blen, fh) != blen) return -1;
    static const uint8_t zeros[4] = {0};
    if (pad && fwrite(zeros, 1, pad, fh) != pad) return -1;
    if (fwrite(&total, 4, 1, fh) != 1) return -1;
    return 0;
}

static int write_shb(FILE* fh)
{
    uint8_t  body[16];
    uint32_t magic = PCAPNG_BO;
    memcpy(body, &magic, 4);
    uint16_t maj = 1, min = 0;
    memcpy(body + 4, &maj, 2);
    memcpy(body + 6, &min, 2);
    int64_t section_len = -1;
    memcpy(body + 8, &section_len, 8);
    return write_block(fh, BT_SHB, body, sizeof body);
}

static int write_idb(FILE* fh, uint16_t link_type, uint32_t snaplen)
{
    uint8_t  body[8];
    uint16_t reserved = 0;
    memcpy(body, &link_type, 2);
    memcpy(body + 2, &reserved, 2);
    memcpy(body + 4, &snaplen, 4);
    return write_block(fh, BT_IDB, body, sizeof body);
}

int sniffer_pcap_open(sniffer_pcap_t* w, const char* path)
{
    if (!w || !path) return -1;
    w->fh        = fopen(path, "wb");
    w->link_type = SNIFFER_DLT_USER0;
    w->snaplen   = 65535;
    if (!w->fh) return -1;
    if (write_shb(w->fh) < 0) return -1;
    if (write_idb(w->fh, (uint16_t)w->link_type, w->snaplen) < 0) return -1;
    return 0;
}

void sniffer_pcap_close(sniffer_pcap_t* w)
{
    if (w && w->fh) {
        fclose(w->fh);
        w->fh = NULL;
    }
}

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

static int write_epb(sniffer_pcap_t* w,
                     const uint8_t* hdr, size_t hlen,
                     const uint8_t* pdu, size_t plen,
                     uint64_t ts_us)
{
    if (!w || !w->fh) return -1;
    if (ts_us == 0) ts_us = now_us();
    size_t   total_payload = hlen + plen;
    if (total_payload > 0xFFFFFFFFu) return -1;
    uint32_t cap_len      = (uint32_t)total_payload;
    /* EPB body: iface(4) ts_high(4) ts_low(4) cap(4) orig(4) data ... */
    size_t   body_size    = 20 + total_payload;
    uint8_t* body         = (uint8_t*)malloc(body_size);
    if (!body) return -1;
    uint32_t iface = 0;
    uint32_t ts_h  = (uint32_t)(ts_us >> 32);
    uint32_t ts_l  = (uint32_t)(ts_us & 0xFFFFFFFFu);
    memcpy(body + 0,  &iface, 4);
    memcpy(body + 4,  &ts_h, 4);
    memcpy(body + 8,  &ts_l, 4);
    memcpy(body + 12, &cap_len, 4);
    memcpy(body + 16, &cap_len, 4);
    if (hlen) memcpy(body + 20, hdr, hlen);
    if (plen) memcpy(body + 20 + hlen, pdu, plen);
    int rc = write_block(w->fh, BT_EPB, body, body_size);
    free(body);
    return rc;
}

int sniffer_pcap_write_pcch(sniffer_pcap_t* w,
                            const uint8_t* pdu, size_t len, uint64_t ts_us)
{
    return write_epb(w, PAGING_HEADER, sizeof PAGING_HEADER, pdu, len, ts_us);
}

int sniffer_pcap_write_sib1(sniffer_pcap_t* w,
                            const uint8_t* pdu, size_t len, uint64_t ts_us)
{
    return write_epb(w, SIB1_HEADER, sizeof SIB1_HEADER, pdu, len, ts_us);
}

int sniffer_pcap_write_sib2(sniffer_pcap_t* w,
                            const uint8_t* pdu, size_t len, uint64_t ts_us)
{
    return write_epb(w, SIB2_HEADER, sizeof SIB2_HEADER, pdu, len, ts_us);
}
