# Multi-radio support (2G / 3G / 4G / 5G)

The v2.3 series adds 2G GSM, 3G UMTS, and an expanded 5G NR surface
alongside the original 4G LTE pipeline. The same downstream tooling
(SQLite store, dashboard, tracker, rogue detector, hub) handles every
generation via a single `radio_type` discriminator.

## What works today

| Generation | Decoder | Realtime capture | Identity capture |
|---|---|---|---|
| 2G GSM | `decoder_2g.py` (TS 04.18 paging types 1/2/3) | `gsm_adapter.py` ← `grgsm_livemon` | IMSI/TMSI (cleartext on PCH) |
| 3G UMTS | `decoder_3g.py` (pycrate TS 25.331) | offline only — see below | IMSI/TMSI/P-TMSI |
| 4G LTE | `decoder.py` (pycrate TS 36.331) | `pdsch_sniffer` (srsRAN_4G) | IMSI/M-TMSI |
| 5G NR | `nr_decoder.py` (pycrate TS 38.331) | `nr_sniffer` skeleton (`--dry-run` works) | ng-5G-S-TMSI / I-RNTI only — **never SUPI** in SA |

## Capture source per generation

### 2G — `grgsm_livemon` adapter

The realtime PHY work is upstream in `gr-gsm`. Run:

```bash
grgsm_livemon --args="rtl=0" -f 947600000 &
srslte-sniffer gsm-adapter --port 4729 --db captures.db
```

`gsm_adapter.py` listens on UDP/4729 for GSMTAP packets, filters to PCH
downlink frames, decodes via `decoder_2g`, and writes the same
`pagings` rows tagged `radio_type='2g'`.

### 3G — offline only

There is **no maintained OSS realtime UMTS PCCH sniffer** as of 2026.
Investing engineer-months on a fresh implementation is bad ROI for an
EOL technology. The decoder side **does** ship — `decoder_3g.decode_pcch`
handles any UMTS PCCH PDU you can extract from a third-party capture
(e.g. an academic dataset or a vendor tool).

If you must capture realtime UMTS, the closest options are:

- `umtsdumper` (last commit ~2018, unmaintained).
- Custom GNURadio flowgraph (academic-only; weeks of work).

### 4G — `pdsch_sniffer`

The original target. Built on `srsRAN_4G`. See
[HIL_VALIDATION.md](HIL_VALIDATION.md).

### 5G NR — `nr_sniffer` skeleton

The skeleton in `src/nr_sniffer/nr_sniffer.c`:

- `--dry-run` synthesises known-good NR PCCH PDUs into journal+pcap,
  letting CI exercise the I/O path without `srsRAN_Project` installed.
- The realtime path requires `srsRAN_Project` (a separate codebase from
  `srsRAN_4G`). Hook is wired through CMake's `SRSRAN_PROJECT_AVAILABLE`
  define; implementation is the next chunk of work — see
  [NR_REALTIME.md](NR_REALTIME.md).

## SUPI / IMSI distinction in 5G

3GPP TS 33.501 mandates that the SUPI is encrypted into a SUCI before
transmission in 5G **standalone**. A passive sniffer **cannot** recover
SUPI in SA — only the SUCI ciphertext, ng-5G-S-TMSI, and I-RNTI surface.

In **5G NSA** the control plane is still LTE, so the existing 4G
sniffer captures all NSA paging.

## DB schema

`pagings.radio_type` is the discriminator. Existing v2 captures are
migrated in place by `CaptureDB.__init__` — the migrations are
idempotent ALTER TABLE ADD COLUMN statements, no data loss.

Identifier columns are now per-radio:

| Column | 2G | 3G | 4G | 5G NR |
|---|---|---|---|---|
| `imsi` | ✓ | ✓ | ✓ | — (encrypted) |
| `tmsi` | ✓ | ✓ | — | — |
| `p_tmsi` | — | ✓ | — | — |
| `mmec` + `m_tmsi` | — | — | ✓ | — |
| `ng_5g_s_tmsi` | — | — | — | ✓ |
| `i_rnti` | — | — | — | ✓ |
| `full_i_rnti` | — | — | — | ✓ |

Tracker (`correlate_subscriber_movement`) is generation-agnostic by
keying on `(kind, primary_id)` so an IMSI seen on 2G + 4G correlates as
the same subscriber.

## Per-generation rogue rules

`rogue_detector.py` adds rules with input snapshots that are
generation-specific:

- **2G**: `detect_a5_0_announcement`, `detect_gsm_loc_update_storm`.
- **3G**: `detect_umts_downgrade_signal`, `detect_umts_reject_storm`.
- **5G NR**: `detect_nr_suci_replay`, `detect_nr_aka_failure_storm`.

The 4G rules unchanged — they apply to LTE traffic captured via
`pdsch_sniffer`.

### Wiring + the data-flow caveat (v2.3.4)

`run_all()` invokes the per-gen rules when their snapshots are
provided; CLI `detect` and `/api/anomalies` build those snapshots
from the `cell_metrics` table.

The fields the rules read (`cipher_mode`, `location_updates_per_min`,
`rrc_reject_per_min`, `advertises_rel99_only`, `suci_replays_per_min`,
`aka_failures_per_min`) **do not flow from any of our capture binaries
today** — they need RRC/MAC counters that the C sniffers don't track.
The `cell_metrics` table is populated by external monitoring code:

```bash
# Example: a 2G monitor scraping gr-gsm logs feeds the cipher-mode it
# observed back to srsLTE-Sniffer.
srslte-sniffer record-metric \
    --db captures.db \
    --radio-type 2g --cell-id 10 --plmn 525-05 \
    --cipher-mode A5/0
```

See the `record-metric` subcommand for the full input shape. Until
external instrumentation is wired, the per-gen rules silently no-op
even with `--radio-type all`.

## What's not done (and why)

- **Realtime 3G** — see "offline only" above.
- **Realtime 5G NR** — `srsRAN_Project` integration. Skeleton ready;
  needs hardware + integration time.
- **Per-radio dashboards** — the existing dashboard is generation-agnostic
  given the `radio_type` column. One unified UI is better than three.
