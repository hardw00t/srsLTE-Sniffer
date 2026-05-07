# Migration: legacy → v2

## Branch is additive

The v2 work lives entirely on the `claude/project-summary-fPHUU` branch.
The original artefacts under `Code/`, `Executables/`, and the top-level
`README.md` are kept verbatim for reference.

## What changed in the legacy code

### `Code/parse_data.c` → `python/srslte_sniffer/decoder.py`

- **Bug fixed**: `is_imsi = true;l` (stray `l`) and the nested
  `if (is_imsi){ if (is_imsi){` blocks are gone — the C file is no longer
  on the hot path at all.
- **Hex-pattern matching gone**: `payload[i] == '9' && payload[i+1] == '5'`
  hard-coded MCC 525 (Singapore). The replacement is an ASN.1 PER decoder
  that handles every PLMN.
- **S-TMSI co-frame parsing**: the original had a TODO for "S-TMSI before
  IMSI in the same frame". The ASN.1 decoder yields a `pagingRecordList`
  so co-frames fall out for free. Validated: ~44k multi-record frames in
  the included demo capture all parse correctly.

### `Code/convert_to_csv.c` → `srslte-sniffer analyze`

- CSV is gone — replaced by SQLite with proper indexes on `(mmec, m_tmsi)`,
  `imsi`, `ts`. CSV export is still possible via `sqlite3 -csv`.
- The "If there is an empty line at the beginning of the file, it will
  crash" gotcha (called out in the legacy README) is gone — the new
  reader skips blank lines.

### `Code/cell_measurement.c` → `src/cell_measurement/cell_measurement.c`

- **SIB2 capture**: the old `// TODO` is implemented. The C side captures
  every SI-window decode; the Python `decoder.extract_sib_container`
  carves out SIB2..SIB13 entries from the `SystemInformation` PDU.

### `Code/pdsch_ue.c` → `src/pdsch_sniffer/sniffer.c`

- Uses the **srsRAN_4G** API (`srsran_*` prefix) — the legacy `srslte_*`
  upstream is dead.
- Uses `srsran_ue_dl_find_and_decode` (the modern one-shot decode call)
  instead of the now-removed `srslte_ue_dl_decode`.
- Outputs **directly to pcapng + journal** — no more text2pcap loop.

### `Executables/loop_catcher.sh` → `scripts/loop_catcher.sh`

- No more rebuilding srsRAN_4G on every iteration.
- Refuses to run without `--i-have-authorization`.
- Multiple EARFCNs configurable on the command line; not hard-coded.
- Calls `srslte-sniffer journal-replay` after each dwell — robust against
  crashes.

## What was kept

- `imsi_pcap_demo.{pcap,txt}` and `Output Files/` are now used as test
  fixtures by the pytest suite.
- The 15-byte mac-lte pseudo-header magic (`01 01 01 02 ff fe ...`) is
  preserved exactly so old captures still dissect cleanly in Wireshark.

## Compatibility

- Existing pcap files written by the original tool (DLT 147 / "User 0")
  are read transparently by `srslte-sniffer analyze`.
- New captures use **pcapng** (richer metadata, multi-block) but Wireshark
  reads both interchangeably.
- The journal format is a new on-disk format — only the new tools read it.
