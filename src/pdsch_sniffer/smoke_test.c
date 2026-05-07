/*
 * smoke_test.c — exercises pcap_writer + journal without any RF stack.
 * Used by CMake's add_test() to keep the I/O code honest in CI.
 */
#include "journal.h"
#include "pcap_writer.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int file_size(const char* path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int)st.st_size;
}

static int read_all(const char* path, uint8_t* out, size_t cap)
{
    FILE* fh = fopen(path, "rb");
    if (!fh) return -1;
    size_t n = fread(out, 1, cap, fh);
    fclose(fh);
    return (int)n;
}

int main(void)
{
    const char* pcap_path    = "smoke.pcapng";
    const char* journal_path = "smoke.journal";
    unlink(pcap_path);
    unlink(journal_path);

    /* ------------------- pcap writer ------------------- */
    {
        sniffer_pcap_t w;
        if (sniffer_pcap_open(&w, pcap_path) < 0) {
            fprintf(stderr, "pcap open failed\n");
            return 1;
        }
        uint8_t pdu[] = {0x40, 0x01, 0x6c, 0x44, 0x5a, 0x82, 0x00,
                         0xda, 0xbf, 0x69, 0x60, 0x45, 0x00, 0x00};
        sniffer_pcap_write_pcch(&w, pdu, sizeof pdu, 1730000000000000ull);
        sniffer_pcap_write_sib1(&w, pdu, sizeof pdu, 1730000000010000ull);
        sniffer_pcap_write_sib2(&w, pdu, sizeof pdu, 1730000000020000ull);
        sniffer_pcap_close(&w);
    }
    /* Verify it begins with the pcapng SHB block type. */
    uint8_t hdr[4];
    if (read_all(pcap_path, hdr, sizeof hdr) != 4) return 2;
    if (!(hdr[0] == 0x0A && hdr[1] == 0x0D && hdr[2] == 0x0D && hdr[3] == 0x0A)) {
        fprintf(stderr, "pcapng SHB magic missing: %02x %02x %02x %02x\n",
                hdr[0], hdr[1], hdr[2], hdr[3]);
        return 3;
    }
    if (file_size(pcap_path) < 100) {
        fprintf(stderr, "pcapng too small: %d\n", file_size(pcap_path));
        return 4;
    }

    /* ------------------- journal ------------------- */
    {
        sniffer_journal_t j;
        if (sniffer_journal_open(&j, journal_path) < 0) return 5;
        uint8_t pdu[] = {0xde, 0xad, 0xbe, 0xef};
        sniffer_journal_write(&j, SNIFFER_JOURNAL_PCCH,
                              0x1122334455667788ull, pdu, sizeof pdu);
        sniffer_journal_close(&j);
    }
    /* magic 'SRLS' little-endian, version 1, kind 1, ts ..., len 4, payload */
    uint8_t buf[64];
    int     got = read_all(journal_path, buf, sizeof buf);
    if (got != 4 + 4 + 1 + 8 + 4 + 4) {
        fprintf(stderr, "journal size wrong: %d\n", got);
        return 6;
    }
    /* magic */
    if (buf[0] != 0x53 || buf[1] != 0x4C || buf[2] != 0x52 || buf[3] != 0x53) {
        fprintf(stderr, "journal magic wrong\n");
        return 7;
    }
    if (buf[8] != SNIFFER_JOURNAL_PCCH) {
        fprintf(stderr, "journal kind wrong: %d\n", buf[8]);
        return 8;
    }
    /* len = 4 */
    if (!(buf[17] == 4 && buf[18] == 0 && buf[19] == 0 && buf[20] == 0)) {
        fprintf(stderr, "journal len field wrong\n");
        return 9;
    }
    if (memcmp(buf + 21, "\xde\xad\xbe\xef", 4) != 0) {
        fprintf(stderr, "journal payload wrong\n");
        return 10;
    }

    unlink(pcap_path);
    unlink(journal_path);
    fprintf(stderr, "smoke test ok\n");
    return 0;
}
