# 5G NR realtime sniffing — design (skeleton implemented)

This codebase has the **decoder side** of NR support today
(`python/srslte_sniffer/nr_decoder.py`), validated against pycrate's
TS 38.331 PCCH/BCCH definitions. Captures from a separate NR sniffer
can be analysed with the existing pipeline.

What's **missing** is a realtime NR sniffer analogous to the LTE
`pdsch_sniffer` C binary. This document captures the path to closing
that gap.

## Why this is harder than LTE

1. The maintained codebase is **`srsRAN_Project`**, not `srsRAN_4G`.
   The two share heritage but diverged. Our `pdsch_sniffer.c` ports
   are LTE-only.

2. NR PDCCH search is more complex (multiple monitoring occasions per
   slot, per-CORESET). The existing srsRAN_4G `pdsch_ue.c` example
   doesn't have a direct equivalent we can copy from.

3. The information value of sniffing is **lower**:
   - 5G SA encrypts SUPI into SUCI before transmission. There is
     **no plaintext IMSI on the air** in standalone 5G.
   - 5G NSA still uses LTE for paging, so an LTE sniffer captures
     all SA → NSA roaming subscriber traffic anyway.

## Recommended approach

If realtime NR observability is needed, the lowest-risk path is:

### Phase 1 — Capture-only research mode (1–2 weeks)

Adapt `srsRAN_Project`'s built-in `gnb_capture` (or equivalent
example in the project) to dump PCCH PDUs to our journal format. No
custom DSP — just a wrapper around the existing capture path.

- Output: NR PCCH PDUs in the same journal format as LTE.
- The Python `nr_decoder` already handles the rest.

### Phase 2 — Standalone NR PDCCH search (4–6 weeks)

If the dependency on `srsRAN_Project` becomes painful, fork their
PDCCH search routine and reduce it to a paging-RNTI-only path:

- New CMake subtree under `src/nr_sniffer/`.
- Reuses the existing `pcap_writer` and `journal` libraries
  byte-for-byte (the headers are 5G-aware via the `mac-nr-framed`
  Wireshark dissector — same DLT 147 trick).
- Per-CORESET monitoring with hardcoded paging RNTI (0xFFFE same
  as LTE).

### Phase 3 — Multi-cell + carrier-aggregation (open-ended)

Parking-lot — only worth doing if research grows to need it.

## What's safe to do now

Without doing any of the above, you can today:

- Decode any NR PCCH/BCCH PDU offline:
  ```python
  from srslte_sniffer.nr_decoder import decode_nr_pcch, extract_nr_paging_records
  res = decode_nr_pcch(pdu_bytes)
  ```
- Re-use the entire downstream pipeline (DB, dashboard, tracker,
  rogue detector) — they're identifier-agnostic. NR S-TMSI
  (`ng-5G-S-TMSI`) flows through the same plumbing.

## Trigger conditions

- A user gets a 5G-SA testbed with an NR-capable SDR and wants live
  capture. Start with Phase 1.
- A research project asks for NR-only sniffing. Skip to Phase 2.

The decoder side has been future-proofed; the radio side is the
remaining gap.
