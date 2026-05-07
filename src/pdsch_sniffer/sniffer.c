/*
 * sniffer.c — modernised port of the original pdsch_ue.c IMSI catcher.
 *
 * Key differences vs. the legacy `Code/pdsch_ue.c`:
 *
 *   * srsRAN_4G API (srsran_* prefix) instead of dead srsLTE.
 *   * Drops the ASCII-text dump pipeline (parse_data.c → text2pcap →
 *     convert_to_csv) in favour of:
 *         - direct pcapng output (pcap_writer.c)
 *         - append-only journal (journal.c) for crash recovery
 *     The Python analyzer runs as a separate consumer over the journal.
 *   * Removes the typo bug (`is_imsi = true;l`) and the nested
 *     `if (is_imsi){if (is_imsi){` from the legacy hex heuristic.
 *   * Removes the hardcoded MCC-525 and "9..8" pattern matching — that
 *     job is now done by the ASN.1 RRC decoder downstream.
 *
 * This file targets srsRAN_4G master at the time of writing; it depends on
 * `srsran_ue_dl_find_and_decode` rather than the legacy `srslte_ue_dl_decode`.
 *
 * IMPORTANT: This binary captures cellular control traffic. Run only on a
 * private eNB or with documented authorisation. See LEGAL.md.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "journal.h"
#include "pcap_writer.h"

#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* srsRAN_4G headers — only included when SRSRAN_AVAILABLE is defined so
 * the file compiles under CI without a full srsRAN install (the journal +
 * pcap writers are tested independently). */
#ifdef SRSRAN_AVAILABLE
#include "srsran/phy/io/filesink.h"
#include "srsran/phy/rf/rf.h"
#include "srsran/srsran.h"
#endif

typedef struct {
    /* RF */
    double      rf_freq;
    float       rf_gain;
    uint32_t    rf_nof_rx_ant;
    char*       rf_dev;
    char*       rf_args;
    /* RNTI to listen for — 0xFFFE = paging RNTI (P-RNTI) */
    uint16_t    rnti;
    /* Output */
    const char* journal_path;
    const char* pcap_path;
    bool        emit_pcap;
    bool        emit_journal;
    /* Lifetime */
    int         dwell_seconds;
    /* Authorisation */
    bool        i_have_authorization;
} prog_args_t;

static void args_default(prog_args_t* a)
{
    a->rf_freq              = 0.0;
    a->rf_gain              = 70.0f;
    a->rf_nof_rx_ant        = 1;
    a->rf_dev               = NULL;
    a->rf_args              = "";
    a->rnti                 = 0xFFFE;
    a->journal_path         = "captures.journal";
    a->pcap_path            = "captures.pcapng";
    a->emit_pcap            = true;
    a->emit_journal         = true;
    a->dwell_seconds        = 240;
    a->i_have_authorization = false;
}

static void usage(const char* argv0)
{
    fprintf(stderr,
        "Usage: %s -f <freq_hz> [options]\n"
        "  -f <hz>             Centre frequency (Hz). Required.\n"
        "  -r <rnti>           RNTI in hex (default 0xFFFE = P-RNTI).\n"
        "  -g <gain>           RF gain (default 70).\n"
        "  -A <nrx>            Number of RX antennas (default 1).\n"
        "  -d <args>           RF args string.\n"
        "  -j <path>           Journal output (default captures.journal).\n"
        "  -p <path>           pcapng output (default captures.pcapng).\n"
        "  -t <seconds>        Dwell time (default 240).\n"
        "  --i-have-authorization  Required to begin capture.\n"
        "  -h                  This help.\n",
        argv0);
}

static bool parse_args(int argc, char** argv, prog_args_t* a)
{
    args_default(a);
    for (int i = 1; i < argc; ++i) {
        const char* opt = argv[i];
        if (!strcmp(opt, "-h") || !strcmp(opt, "--help")) {
            usage(argv[0]);
            return false;
        }
        if (!strcmp(opt, "--i-have-authorization")) {
            a->i_have_authorization = true;
            continue;
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "missing value for %s\n", opt);
            return false;
        }
        const char* val = argv[++i];
        if (!strcmp(opt, "-f")) {
            a->rf_freq = strtod(val, NULL);
        } else if (!strcmp(opt, "-r")) {
            a->rnti = (uint16_t)strtoul(val, NULL, 0);
        } else if (!strcmp(opt, "-g")) {
            a->rf_gain = (float)strtod(val, NULL);
        } else if (!strcmp(opt, "-A")) {
            a->rf_nof_rx_ant = (uint32_t)strtoul(val, NULL, 0);
        } else if (!strcmp(opt, "-d")) {
            a->rf_args = (char*)val;
        } else if (!strcmp(opt, "-j")) {
            a->journal_path = val;
        } else if (!strcmp(opt, "-p")) {
            a->pcap_path = val;
        } else if (!strcmp(opt, "-t")) {
            a->dwell_seconds = atoi(val);
        } else {
            fprintf(stderr, "unknown option: %s\n", opt);
            return false;
        }
    }
    if (a->rf_freq <= 0.0) {
        fprintf(stderr, "missing -f <freq_hz>\n");
        return false;
    }
    return true;
}

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

/* ------------------------------------------------------------------ */
/*  When SRSRAN_AVAILABLE is defined the rest of the file is the radio
 *  loop. Otherwise we provide a stub that prints a clear error so CI
 *  smoke-tests can `--help` the binary even on systems without srsRAN.
 */
/* ------------------------------------------------------------------ */

#ifndef SRSRAN_AVAILABLE
int main(int argc, char** argv)
{
    prog_args_t a;
    if (!parse_args(argc, argv, &a)) return 1;
    fprintf(stderr,
        "sniffer was built without SRSRAN_AVAILABLE — capture mode is "
        "disabled in this binary. Rebuild with srsRAN_4G installed to "
        "enable RF capture. (--help works either way.)\n");
    return 2;
}
#else  /* SRSRAN_AVAILABLE */

/* Capture state */
typedef struct {
    sniffer_pcap_t*    pcap;
    sniffer_journal_t* journal;
    bool               emit_pcap;
    bool               emit_journal;
} sink_t;

static void emit_pcch(sink_t* s, const uint8_t* pdu, size_t len)
{
    uint64_t ts = now_us();
    if (s->emit_pcap && s->pcap)
        sniffer_pcap_write_pcch(s->pcap, pdu, len, ts);
    if (s->emit_journal && s->journal)
        sniffer_journal_write(s->journal, SNIFFER_JOURNAL_PCCH,
                              ts, pdu, (uint32_t)len);
}

int main(int argc, char** argv)
{
    prog_args_t a;
    if (!parse_args(argc, argv, &a)) return 1;
    if (!a.i_have_authorization) {
        fprintf(stderr,
            "Refusing to capture: pass --i-have-authorization once you have "
            "lawful authorisation. See LEGAL.md.\n");
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    sniffer_pcap_t    pcap   = {0};
    sniffer_journal_t journal = {0};
    sink_t            sink   = {0};
    sink.emit_pcap   = a.emit_pcap;
    sink.emit_journal = a.emit_journal;

    if (a.emit_pcap && sniffer_pcap_open(&pcap, a.pcap_path) < 0) {
        fprintf(stderr, "pcap open failed: %s\n", a.pcap_path);
        return 3;
    }
    sink.pcap = &pcap;

    if (a.emit_journal && sniffer_journal_open(&journal, a.journal_path) < 0) {
        fprintf(stderr, "journal open failed: %s\n", a.journal_path);
        sniffer_pcap_close(&pcap);
        return 3;
    }
    sink.journal = &journal;

    /* ---- RF + DSP setup (srsRAN_4G) -------------------------------- */

    srsran_rf_t rf;
    if (srsran_rf_open_devname(&rf, a.rf_dev, a.rf_args, a.rf_nof_rx_ant)) {
        fprintf(stderr, "RF open failed\n");
        return 4;
    }
    srsran_rf_set_rx_gain(&rf, a.rf_gain);
    srsran_rf_set_rx_freq(&rf, a.rf_nof_rx_ant, a.rf_freq);

    srsran_cell_t cell = {0};
    if (srsran_ue_cellsearch_scan_and_select_cell(&rf,
                                                  a.rf_nof_rx_ant,
                                                  &cell) < 0) {
        fprintf(stderr, "no cell found at %.0f Hz\n", a.rf_freq);
        srsran_rf_close(&rf);
        sniffer_pcap_close(&pcap);
        sniffer_journal_close(&journal);
        return 5;
    }

    srsran_ue_sync_t  ue_sync = {0};
    srsran_ue_mib_t   ue_mib  = {0};
    srsran_ue_dl_t    ue_dl   = {0};
    srsran_ue_dl_cfg_t   ue_dl_cfg   = {0};
    srsran_pdsch_cfg_t   pdsch_cfg   = {0};
    srsran_dl_sf_cfg_t   sf_cfg      = {0};

    if (srsran_ue_sync_init_multi(&ue_sync, cell.nof_prb, false,
                                  NULL, NULL, a.rf_nof_rx_ant) < 0)
        goto fatal;
    if (srsran_ue_sync_set_cell(&ue_sync, cell) < 0)
        goto fatal;
    if (srsran_ue_dl_init(&ue_dl, NULL, cell.nof_prb, a.rf_nof_rx_ant) < 0)
        goto fatal;
    if (srsran_ue_dl_set_cell(&ue_dl, cell) < 0)
        goto fatal;
    srsran_ue_dl_set_rnti(&ue_dl, a.rnti);

    /* ---- Capture loop --------------------------------------------- */

    uint8_t* data[SRSRAN_MAX_CODEWORDS] = {0};
    for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; ++i)
        data[i] = (uint8_t*)malloc(SRSRAN_MAX_BUFFER_SIZE_BYTES);
    bool acks[SRSRAN_MAX_CODEWORDS] = {false};

    time_t deadline = time(NULL) + a.dwell_seconds;

    while (!g_stop && time(NULL) < deadline) {
        int n = srsran_ue_sync_zerocopy(&ue_sync, NULL);
        if (n < 0) continue;
        if (n != 1) continue;

        sf_cfg.tti = srsran_ue_sync_get_sfidx(&ue_sync);

        int dec = srsran_ue_dl_find_and_decode(&ue_dl,
                                               &sf_cfg,
                                               &ue_dl_cfg,
                                               &pdsch_cfg,
                                               data,
                                               acks);
        if (dec > 0) {
            /* dec is the bit length of the decoded payload — we want
             * bytes for the journal. */
            size_t bytes = (size_t)((dec + 7) / 8);
            emit_pcch(&sink, data[0], bytes);
        }
    }

    for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; ++i)
        free(data[i]);

    srsran_ue_dl_free(&ue_dl);
    srsran_ue_sync_free(&ue_sync);
    srsran_rf_close(&rf);
    sniffer_pcap_close(&pcap);
    sniffer_journal_close(&journal);
    return 0;

fatal:
    fprintf(stderr, "DSP init failed\n");
    srsran_rf_close(&rf);
    sniffer_pcap_close(&pcap);
    sniffer_journal_close(&journal);
    return 6;
}

#endif /* SRSRAN_AVAILABLE */
