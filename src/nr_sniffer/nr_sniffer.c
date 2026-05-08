/*
 * nr_sniffer.c — 5G NR PCCH paging sniffer skeleton.
 *
 * Status: SKELETON. The realtime NR PHY work depends on srsRAN_Project
 * (a separate codebase from srsRAN_4G). This file is the scaffold that
 * mirrors src/pdsch_sniffer/sniffer.c — same I/O contract, --dry-run
 * support, same journal/pcap output — so the Python analyzer side
 * doesn't change when a realtime backend lands.
 *
 * What works today:
 *   - --dry-run: synthesises a known-good 5G NR PCCH-Message PDU into
 *     the journal + pcap. Lets the C-side wiring be CI-tested.
 *
 * What needs srsRAN_Project to fill in:
 *   - srsran_du_high or equivalent NR PHY initialisation,
 *   - PDCCH search across the configured CORESETs,
 *   - PDSCH decode with the paging RNTI (default P-RNTI = 0xFFFE).
 *   The existing sniffer.c is the reference for pattern.
 *
 * This file is intentionally small. Most of the analytical work happens
 * in Python (nr_decoder.py). The realtime path is a wrapper.
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

typedef struct {
    double      rf_freq;
    float       rf_gain;
    uint32_t    rf_nof_rx_ant;
    char*       rf_args;
    const char* journal_path;
    const char* pcap_path;
    int         dwell_seconds;
    bool        i_have_authorization;
    bool        dry_run;
    int         dry_run_count;
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
        "Usage: %s -f <hz> [options]\n"
        "  -f <hz>             NR carrier centre freq (Hz). Required for live mode.\n"
        "  -g <gain>           RF gain (default 70).\n"
        "  -t <seconds>        Dwell time (default 60).\n"
        "  -j <path>           Journal output (default nr.journal).\n"
        "  -p <path>           pcapng output (default nr.pcapng).\n"
        "  --dry-run           Skip RF; synthesise known-good NR PCCH PDUs.\n"
        "  --dry-run-count N   How many PDUs to synthesise (default 50).\n"
        "  --i-have-authorization  Required for live mode.\n",
        a0);
}

static bool parse(int argc, char** argv, args_t* a)
{
    a->rf_freq = 0.0;
    a->rf_gain = 70.0f;
    a->rf_nof_rx_ant = 1;
    a->rf_args = "";
    a->journal_path = "nr.journal";
    a->pcap_path = "nr.pcapng";
    a->dwell_seconds = 60;
    a->i_have_authorization = false;
    a->dry_run = false;
    a->dry_run_count = 50;

    for (int i = 1; i < argc; ++i) {
        const char* o = argv[i];
        if (!strcmp(o, "-h") || !strcmp(o, "--help")) {
            usage(argv[0]);
            return false;
        }
        if (!strcmp(o, "--i-have-authorization")) {
            a->i_have_authorization = true;
            continue;
        }
        if (!strcmp(o, "--dry-run")) {
            a->dry_run = true;
            continue;
        }
        if (i + 1 >= argc) return false;
        const char* v = argv[++i];
        if      (!strcmp(o, "-f")) a->rf_freq = strtod(v, NULL);
        else if (!strcmp(o, "-g")) a->rf_gain = (float)strtod(v, NULL);
        else if (!strcmp(o, "-d")) a->rf_args = (char*)v;
        else if (!strcmp(o, "-j")) a->journal_path = v;
        else if (!strcmp(o, "-p")) a->pcap_path = v;
        else if (!strcmp(o, "-t")) a->dwell_seconds = atoi(v);
        else if (!strcmp(o, "--dry-run-count")) a->dry_run_count = atoi(v);
        else { fprintf(stderr, "unknown: %s\n", o); return false; }
    }
    if (!a->dry_run && a->rf_freq <= 0.0) return false;
    return true;
}

/* Real 5G NR PCCH-Message PDUs encoded via pycrate against TS 38.331,
 * verified to decode through srslte_sniffer.nr_decoder. Each carries
 * actual paging records — empty/synthetic PDUs would defeat the purpose
 * of dry-run as an end-to-end pipeline check.
 *
 * - DRY_PDU_NG_STMSI: single ng-5G-S-TMSI record  (8 bytes)
 * - DRY_PDU_IRNTI:    single fullI-RNTI record    (7 bytes)
 * - DRY_PDU_MULTI:    two ng-5G-S-TMSI records    (15 bytes)
 */
static const uint8_t DRY_PDU_NG_STMSI[] = {
    0x20, 0x03, 0x2b, 0xfa, 0xea, 0xf8, 0x48, 0xd0,
};
static const uint8_t DRY_PDU_IRNTI[] = {
    0x20, 0x04, 0x48, 0xd1, 0x59, 0xe2, 0x68,
};
static const uint8_t DRY_PDU_MULTI[] = {
    0x20, 0x43, 0x7a, 0xb6, 0xfb, 0xbc, 0x00, 0x04,
    0x37, 0xab, 0x6f, 0xbb, 0xc0, 0x00, 0x80,
};

typedef struct {
    const uint8_t* bytes;
    size_t         len;
} dry_pdu_t;

static const dry_pdu_t DRY_PDUS[] = {
    {DRY_PDU_NG_STMSI, sizeof DRY_PDU_NG_STMSI},
    {DRY_PDU_IRNTI,    sizeof DRY_PDU_IRNTI},
    {DRY_PDU_MULTI,    sizeof DRY_PDU_MULTI},
};
#define DRY_PDU_VARIANTS (sizeof(DRY_PDUS) / sizeof(DRY_PDUS[0]))

static int run_dry(const args_t* a)
{
    sniffer_pcap_t    pcap   = {0};
    sniffer_journal_t journal = {0};
    if (sniffer_pcap_open(&pcap, a->pcap_path) < 0) {
        fprintf(stderr, "pcap open failed\n"); return 3;
    }
    if (sniffer_journal_open(&journal, a->journal_path) < 0) {
        fprintf(stderr, "journal open failed\n"); return 3;
    }
    int n = a->dry_run_count > 0 ? a->dry_run_count : 50;
    for (int i = 0; i < n; ++i) {
        const dry_pdu_t* p   = &DRY_PDUS[i % DRY_PDU_VARIANTS];
        uint64_t         ts  = now_us() + (uint64_t)i;
        sniffer_pcap_write_pcch(&pcap, p->bytes, p->len, ts);
        sniffer_journal_write(&journal, SNIFFER_JOURNAL_PCCH, ts,
                              p->bytes, (uint32_t)p->len);
    }
    sniffer_pcap_close(&pcap);
    sniffer_journal_close(&journal);
    fprintf(stderr,
        "nr_sniffer dry-run: wrote %d NR PCCH records to %s + %s\n",
        n, a->pcap_path, a->journal_path);
    return 0;
}

#ifdef SRSRAN_PROJECT_AVAILABLE
/* The realtime path needs srsRAN_Project — see docs/NR_REALTIME.md.
 * Implementation pending; until then the binary refuses live mode. */
static int run_live(const args_t* a)
{
    (void)a;
    fprintf(stderr,
        "live NR capture not yet implemented — see docs/NR_REALTIME.md "
        "for the integration plan. Use --dry-run for journal/pcap I/O "
        "validation in the meantime.\n");
    return 4;
}
#else
static int run_live(const args_t* a)
{
    (void)a;
    fprintf(stderr,
        "Built without SRSRAN_PROJECT_AVAILABLE — live NR capture is "
        "disabled. Use --dry-run, or rebuild with srsRAN_Project.\n");
    return 2;
}
#endif

int main(int argc, char** argv)
{
    args_t a;
    if (!parse(argc, argv, &a)) return 1;
    if (a.dry_run) return run_dry(&a);
    if (!a.i_have_authorization) {
        fprintf(stderr, "Refusing — pass --i-have-authorization.\n");
        return 2;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    return run_live(&a);
}
