# Rust decoder — design (deferred)

> Status: **deferred**. This document captures why, what, and what to
> do when the decision is revisited.

## Why deferred

The current pycrate decoder benchmarks at **~27,000 packets/sec** on one
core in this sandbox (see `tools/benchmark.py`). For all currently scoped
use cases this is more than enough:

| Use case | Required throughput | pycrate? |
|---|---|---|
| Live dashboard, single cell | <500 pkt/s | Yes |
| 2–4-cell scanner sweep | <2,000 pkt/s | Yes |
| Bulk pcap re-analysis | offline, batch | Yes |
| Multi-cell paging-storm replay | 50,000+ pkt/s | Marginal |

A Rust decoder would close the last row, but at 27k pkt/s pycrate is
already well above the trigger originally planned (10k pkt/s). The
rewrite is large (generated decoder for TS 36.331 + 38.331, plus pyo3
binding, plus parity tests) and we don't have a use case in production
yet that breaks pycrate.

## What it would look like

1. **ASN.1 generator**: pick `rasn` or `asn1c → pyo3 wrapper`.
   `rasn`'s pure-Rust generator is the cleanest path; it has UPER
   support, generated code is `no_std`-compatible, and it has been
   used in commercial cellular decoders.

2. **Module shape**:
   ```text
   crates/
     srsran-rrc-codec/      — generated TS 36.331 + 38.331 types
     srsran-rrc-py/         — pyo3 wrapper exposing `decode_pcch_uper(bytes) -> dict`
   ```
   Same Python API as `srslte_sniffer.decoder` (PCCHResult etc.) — the
   call site doesn't change, only the implementation.

3. **Error tolerance**: `rasn` allows lazy decoding so unknown-extension
   warnings (the ~0.01% pycrate currently fails on) become recoverable
   rather than fatal.

4. **Build**: `maturin` for wheel publishing; CI extends with a Rust
   toolchain step that's cached.

5. **Parity test**: `tools/dissector_diff.py` extended to diff the Rust
   and pycrate outputs over the demo capture; CI-blocking.

## Trigger conditions to revisit

Revisit the decision if any of these become true:

- Throughput requirement exceeds 10k pkt/s (e.g. multi-cell deployment).
- pycrate's "unknown extension index" failure rate trends above 1%
  (would mean newer 3GPP releases with extensions pycrate doesn't track).
- We start running on power-constrained hosts where pycrate's CPU
  budget hurts (e.g. embedded gateway).

## Estimated effort

- **2 weeks** for `rasn` codegen + parity tests for LTE PCCH/BCCH only
  (the hot path).
- **+2 weeks** for NR (TS 38.331) and SIB2..SIB13 coverage.
- **+1 week** for pyo3 bindings, wheel publishing, and CI integration.

Total roughly five weeks of one engineer. Don't start without a use
case in the trigger conditions above.
