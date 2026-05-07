#!/usr/bin/env python3
"""Decoder-throughput benchmark.

Run:  python3 tools/benchmark.py [pcap_or_txt] [--limit N]

Prints decode rate (packets/sec) and per-packet latency. Used to track
performance regressions and to motivate the Rust port (see
docs/RUST_DECODER.md).
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "python"))

from srslte_sniffer.decoder import (  # noqa: E402
    decode_pcch,
    extract_paging_records,
)
from srslte_sniffer.pcap_io import read_capture  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "input", type=Path, nargs="?",
        default=_REPO_ROOT / "imsi_pcap_demo.txt",
    )
    ap.add_argument("--limit", type=int, default=50_000)
    ap.add_argument("--warmup", type=int, default=200)
    args = ap.parse_args()

    if not args.input.exists():
        print(f"input not found: {args.input}", file=sys.stderr)
        return 1

    frames = list(read_capture(str(args.input)))[: args.limit + args.warmup]
    if len(frames) < args.warmup + 1000:
        print(f"warning: only {len(frames)} frames available", file=sys.stderr)

    # Warm-up — first calls trigger lazy imports + JIT-ish behaviours.
    for f in frames[: args.warmup]:
        res = decode_pcch(f.payload)
        if res.ok:
            extract_paging_records(res)

    timed = frames[args.warmup : args.warmup + args.limit]
    n = len(timed)

    started = time.perf_counter()
    ok = 0
    for f in timed:
        res = decode_pcch(f.payload)
        if res.ok:
            ok += 1
            extract_paging_records(res)
    elapsed = time.perf_counter() - started

    rate = n / elapsed if elapsed > 0 else 0.0
    per = elapsed / n * 1e6 if n else 0.0
    print(
        f"decoded {n} packets in {elapsed:.3f}s — "
        f"{rate:,.0f} pkt/s, {per:.1f} µs/pkt, "
        f"success {ok}/{n} ({100 * ok / n:.2f}%)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
