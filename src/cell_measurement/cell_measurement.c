/*
 * cell_measurement.c — modernised cell scanner that captures both SIB1
 * AND SIB2 (the legacy version had SIB2 marked TODO).
 *
 * Output is written through pcap_writer.c using SIB1/SIB2 framing so the
 * Python decoder side can carve PLMN, TAC, cell-ID, and the SIB2 system-
 * info payload out without ever touching the legacy hex pattern matcher.
 *
 * Build: same CMake target tree as pdsch_sniffer; relies on srsRAN_4G
 * headers when SRSRAN_AVAILABLE is defined, otherwise builds as a stub.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "../pdsch_sniffer/journal.h"
#include "../pdsch_sniffer/pcap_writer.h"

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef SRSRAN_AVAILABLE
#include "srsran/srsran.h"
#endif

typedef struct {
    double      rf_freq;
    float       rf_gain;
    uint32_t    rf_nof_rx_ant;
    char*       rf_args;
    const char* journal_path;
    const char* pcap_path;
    int         dwell_seconds;
    bool        i_have_authorization;
} args_t;

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

static void usage(const char* a0)
{
    fprintf(stderr,
        "Usage: %s -f <hz> [-g gain] [-A nrx] [-t seconds] "
        "[-j journal] [-p pcap] --i-have-authorization\n", a0);
}

static bool parse(int argc, char** argv, args_t* a)
{
    a->rf_freq = 0.0;
    a->rf_gain = 70.0f;
    a->rf_nof_rx_ant = 1;
    a->rf_args = "";
    a->journal_path = "cells.journal";
    a->pcap_path = "cells.pcapng";
    a->dwell_seconds = 60;
    a->i_have_authorization = false;
    for (int i = 1; i < argc; ++i) {
        const char* o = argv[i];
        if (!strcmp(o, "-h")) { usage(argv[0]); return false; }
        if (!strcmp(o, "--i-have-authorization")) {
            a->i_have_authorization = true;
            continue;
        }
        if (i + 1 >= argc) return false;
        const char* v = argv[++i];
        if      (!strcmp(o, "-f")) a->rf_freq = strtod(v, NULL);
        else if (!strcmp(o, "-g")) a->rf_gain = (float)strtod(v, NULL);
        else if (!strcmp(o, "-A")) a->rf_nof_rx_ant = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(o, "-d")) a->rf_args = (char*)v;
        else if (!strcmp(o, "-j")) a->journal_path = v;
        else if (!strcmp(o, "-p")) a->pcap_path = v;
        else if (!strcmp(o, "-t")) a->dwell_seconds = atoi(v);
        else { fprintf(stderr, "unknown: %s\n", o); return false; }
    }
    return a->rf_freq > 0.0;
}

#ifndef SRSRAN_AVAILABLE
int main(int argc, char** argv)
{
    args_t a;
    if (!parse(argc, argv, &a)) return 1;
    fprintf(stderr,
        "cell_measurement built without SRSRAN_AVAILABLE — capture is "
        "disabled in this binary. Install srsRAN_4G and rebuild.\n");
    return 2;
}
#else

int main(int argc, char** argv)
{
    args_t a;
    if (!parse(argc, argv, &a)) return 1;
    if (!a.i_have_authorization) {
        fprintf(stderr, "Refusing — see LEGAL.md.\n");
        return 2;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    sniffer_pcap_t    pcap   = {0};
    sniffer_journal_t journal = {0};
    if (sniffer_pcap_open(&pcap, a.pcap_path) < 0) {
        fprintf(stderr, "pcap open failed\n"); return 3;
    }
    if (sniffer_journal_open(&journal, a.journal_path) < 0) {
        fprintf(stderr, "journal open failed\n"); return 3;
    }

    srsran_rf_t rf;
    if (srsran_rf_open_devname(&rf, NULL, a.rf_args, a.rf_nof_rx_ant)) {
        fprintf(stderr, "RF open failed\n"); return 4;
    }
    srsran_rf_set_rx_gain(&rf, a.rf_gain);
    srsran_rf_set_rx_freq(&rf, a.rf_nof_rx_ant, a.rf_freq);

    srsran_cell_t cell = {0};
    if (srsran_ue_cellsearch_scan_and_select_cell(&rf,
                                                  a.rf_nof_rx_ant,
                                                  &cell) < 0) {
        fprintf(stderr, "no cell\n"); return 5;
    }

    /* PRACH/SIB pull loop — every (sfn % 2) == 0, sfidx == 5 carries
     * SIB1 in standard FDD scheduling. SIB2..SIB13 ride on the same
     * SI-window in subsequent matching subframes; the actual position is
     * determined by SIB1's schedulingInfoList, which the Python decoder
     * extracts. We therefore capture *all* DL-SCH-decoded subframes in
     * the SI window and tag them with the inferred SIB type by length.
     */
    srsran_ue_sync_t   ue_sync = {0};
    srsran_ue_dl_t     ue_dl   = {0};
    srsran_ue_dl_cfg_t cfg     = {0};
    srsran_pdsch_cfg_t pdsch   = {0};
    srsran_dl_sf_cfg_t sf_cfg  = {0};
    srsran_ue_sync_init_multi(&ue_sync, cell.nof_prb, false, NULL, NULL,
                              a.rf_nof_rx_ant);
    srsran_ue_sync_set_cell(&ue_sync, cell);
    srsran_ue_dl_init(&ue_dl, NULL, cell.nof_prb, a.rf_nof_rx_ant);
    srsran_ue_dl_set_cell(&ue_dl, cell);
    srsran_ue_dl_set_rnti(&ue_dl, SRSRAN_SIRNTI);

    uint8_t* data[SRSRAN_MAX_CODEWORDS] = {0};
    for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; ++i)
        data[i] = (uint8_t*)malloc(SRSRAN_MAX_BUFFER_SIZE_BYTES);
    bool acks[SRSRAN_MAX_CODEWORDS] = {false};

    time_t deadline = time(NULL) + a.dwell_seconds;
    bool   sib1_seen = false;

    while (!g_stop && time(NULL) < deadline) {
        if (srsran_ue_sync_zerocopy(&ue_sync, NULL) != 1) continue;
        sf_cfg.tti = srsran_ue_sync_get_sfidx(&ue_sync);
        int n = srsran_ue_dl_find_and_decode(&ue_dl, &sf_cfg, &cfg, &pdsch,
                                             data, acks);
        if (n <= 0) continue;
        size_t bytes = (size_t)((n + 7) / 8);
        uint64_t ts = now_us();

        /* The first SIB-window decode is SIB1; subsequent ones are
         * the SystemInformation messages carrying SIB2..SIBn. The
         * Python decoder side discriminates definitively from the
         * decoded BCCH-DL-SCH-Message CHOICE alternative — we just
         * tag here for routing/storage convenience. */
        uint8_t kind;
        if (!sib1_seen) {
            sib1_seen = true;
            sniffer_pcap_write_sib1(&pcap, data[0], bytes, ts);
            kind = SNIFFER_JOURNAL_SIB1;
        } else {
            sniffer_pcap_write_sib2(&pcap, data[0], bytes, ts);
            kind = SNIFFER_JOURNAL_SIB2;
        }
        sniffer_journal_write(&journal, kind, ts, data[0], (uint32_t)bytes);
    }

    for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; ++i) free(data[i]);
    srsran_ue_dl_free(&ue_dl);
    srsran_ue_sync_free(&ue_sync);
    srsran_rf_close(&rf);
    sniffer_pcap_close(&pcap);
    sniffer_journal_close(&journal);
    return 0;
}
#endif
