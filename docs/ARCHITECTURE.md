# Architecture (v2)

```
            ┌──────────────────────────┐
            │   SDR (USRP / BladeRF)   │
            └────────────┬─────────────┘
                         │  IQ samples
                         ▼
            ┌──────────────────────────┐
            │      pdsch_sniffer       │  ← src/pdsch_sniffer/sniffer.c
            │   (modernised pdsch_ue)  │     uses srsRAN_4G API
            └─────┬──────────┬─────────┘
                  │          │
       pcapng ◄───┘          └───► journal (append-only, fsync'd)
       (DLT 147)                   src/pdsch_sniffer/journal.c

            ┌──────────────────────────┐
            │    Python analyzer       │  ← python/srslte_sniffer/
            │  ASN.1 RRC PCCH/BCCH     │     decoder.py + analyzer.py
            └────────────┬─────────────┘
                         │
                         ▼
            ┌──────────────────────────┐
            │      SQLite store        │  ← python/srslte_sniffer/db.py
            └────────────┬─────────────┘
                         │
        ┌────────────────┼────────────────────┐
        ▼                ▼                    ▼
  ┌───────────┐    ┌───────────┐       ┌───────────────┐
  │ dashboard │    │  tracker  │       │ rogue_detector│
  │ (FastAPI) │    │ (TMSI ↔   │       │ (anomaly rules│
  └───────────┘    │  IMSI)    │       │  on cells +   │
                   └───────────┘       │  paging churn)│
                                       └───────────────┘
```

## Design choices

### Why split C / Python?
The realtime PHY loop has hard timing requirements that only C +
srsRAN_4G's optimised PDSCH path can hit on commodity hardware. Everything
*after* the PDU lands in memory has no realtime constraint, so it's much
faster to build and easier to test in Python.

### Why pcapng + a journal?
The original tool wrote a custom ASCII text format that `text2pcap` then
converted offline. That had two failure modes:

1. **Text2pcap startup latency** — at the end of every loop iteration the
   shell spent 10+ s converting; during that window pdsch_ue couldn't run.
2. **Crash safety** — when the sniffer died mid-write, the partial line
   could break `convert_to_csv`.

The journal solves (2) via length-prefixed records and fsync-on-write; the
pcapng writer solves (1) by writing the binary format the analyzer can
read directly.

### Why ASN.1 instead of byte-pattern matching?
The original `print_IMSI` regex (`9 5 ... 8`) was hardcoded for Singapore
MCC 525, fragile on byte alignment, and gave up entirely on:

- multi-record paging frames (S-TMSI before *and* after IMSI)
- IMSI-only pages without a co-located S-TMSI
- non-525 MCCs (Australia 505, Malaysia 502, etc — all locked out)

3GPP defines the wire format as ASN.1 PER. pycrate has a generated
decoder for TS 36.331 (RRC LTE) and TS 38.331 (NR RRC). Using it gives
us:

- Country-portable parsing (any MCC works — no edits required).
- Correct handling of all `PagingRecordList` shapes for free.
- A path to NR captures via the same library.

### Why pluggable dwell function?
`scanner.py` takes a `dwell_fn(earfcn, hz, seconds) -> CellObservation`.
Tests pass a fake; production passes a script that wraps `pdsch_sniffer`.
This keeps the scanner state-machine pure and unit-testable on systems
without an SDR.

### Why hash by default?
IMSI / M-TMSI are personally identifying. The DB stores SHA-256 hashes
unless `--unsafe-raw` is passed, which removes the foot-gun of accidentally
exporting a CSV of subscriber identifiers.

## Module layout

| Path | Role |
|---|---|
| `src/pdsch_sniffer/sniffer.c` | Realtime sniffer; srsRAN_4G port |
| `src/pdsch_sniffer/pcap_writer.{h,c}` | Direct pcapng writer (DLT 147) |
| `src/pdsch_sniffer/journal.{h,c}` | Append-only crash-safe journal |
| `src/cell_measurement/cell_measurement.c` | SIB1 + SIB2 capture |
| `python/srslte_sniffer/decoder.py` | ASN.1 RRC PCCH / BCCH decoders |
| `python/srslte_sniffer/pcap_io.py` | Capture file readers + pcapng writer |
| `python/srslte_sniffer/analyzer.py` | End-to-end pipeline |
| `python/srslte_sniffer/db.py` | SQLite store |
| `python/srslte_sniffer/journal.py` | Python journal reader/writer |
| `python/srslte_sniffer/scanner.py` | EARFCN sweep state machine |
| `python/srslte_sniffer/dashboard.py` | FastAPI live UI |
| `python/srslte_sniffer/tracker.py` | TMSI ↔ IMSI correlation |
| `python/srslte_sniffer/rogue_detector.py` | Defensive anomaly rules |
| `python/srslte_sniffer/nr_decoder.py` | 5G NR research-mode skeleton |
| `python/srslte_sniffer/cli.py` | Click CLI entry-point |
| `scripts/loop_catcher.sh` | Modern run-loop replacement |
| `scripts/dwell.sh` | Per-EARFCN dwell script |

## Test surface

* `python/tests/` — pytest suite, validated against the included
  `imsi_pcap_demo.txt` and `Output Files/imsi.pcap` (≈250k frames).
* `src/pdsch_sniffer/smoke_test.c` — runs in CI without srsRAN to catch
  regressions in the journal/pcapng writers.

## What's *not* here

* The original `Code/` and `Executables/` directories are kept as-is for
  reference. The new entry points are `srslte-sniffer` (Python CLI) and
  `pdsch_sniffer` (C binary built via `cmake --build build`).
* No 5G-NR realtime sniffer is included. The skeleton in
  `nr_decoder.py` decodes captures, not air. A NR realtime path needs
  `srsRAN_Project`, which is a separate project from `srsRAN_4G`.
