/* fileno + fsync require POSIX visibility under strict ISO. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "journal.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int sniffer_journal_open(sniffer_journal_t* j, const char* path)
{
    if (!j || !path) return -1;
    j->fh = fopen(path, "ab");
    return j->fh ? 0 : -1;
}

void sniffer_journal_close(sniffer_journal_t* j)
{
    if (j && j->fh) {
        fclose(j->fh);
        j->fh = NULL;
    }
}

int sniffer_journal_write(sniffer_journal_t* j,
                          uint8_t kind,
                          uint64_t ts_us,
                          const uint8_t* payload,
                          uint32_t len)
{
    if (!j || !j->fh) return -1;
    uint8_t  hdr[4 + 4 + 1 + 8 + 4];
    uint32_t magic = SNIFFER_JOURNAL_MAGIC;
    uint32_t ver   = SNIFFER_JOURNAL_VERSION;
    memcpy(hdr + 0,  &magic, 4);
    memcpy(hdr + 4,  &ver, 4);
    hdr[8] = kind;
    memcpy(hdr + 9,  &ts_us, 8);
    memcpy(hdr + 17, &len, 4);
    if (fwrite(hdr, 1, sizeof hdr, j->fh) != sizeof hdr) return -1;
    if (len && fwrite(payload, 1, len, j->fh) != len) return -1;
    if (fflush(j->fh) != 0) return -1;
    fsync(fileno(j->fh));
    return 0;
}
