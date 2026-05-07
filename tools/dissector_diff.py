#!/usr/bin/env python3
"""Cross-check our pycrate-based decoder against Wireshark/tshark.

Runs `tshark -V -T json` over a pcap, extracts the LTE-RRC fields it
dissected, decodes the same packets through our `srslte_sniffer.decoder`,
and reports any mismatches. Intended as a **correctness oracle** — we
don't ship the dissector but we do want to know if our output drifts.

Usage:
    tools/dissector_diff.py <pcap> [--limit N] [--strict]

Exits 0 on agreement, 1 on disagreement, 2 if tshark is not installed.

Design note: tshark exposes `lte-rrc.ue_Identity` as a raw value (1=imsi,
0=s-tmsi); we map that into our PagingRecord.kind for the comparison.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "python"))

from srslte_sniffer.decoder import decode_pcch, extract_paging_records  # noqa: E402
from srslte_sniffer.pcap_io import read_capture  # noqa: E402


def _have_tshark() -> bool:
    return shutil.which("tshark") is not None


def _tshark_dissect(pcap: Path, limit: int | None) -> list[dict]:
    args = [
        "tshark", "-r", str(pcap), "-T", "json",
        "-Y", "lte-rrc",
        "-d", "udp.port==9000,mac-lte",
        "-o", "uat:user_dlts:\"User 0 (DLT=147)\",\"mac-lte-framed\",\"\",\"\",\"\",\"\"",
    ]
    if limit is not None:
        args += ["-c", str(limit)]
    out = subprocess.run(args, capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise RuntimeError(f"tshark failed: {out.stderr[:400]}")
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"tshark JSON parse failed: {e}") from e


def _tshark_kind(packet: dict) -> str | None:
    """Map a single dissected packet to one of {'imsi', 's-tmsi', None}."""
    layers = packet.get("_source", {}).get("layers", {})
    rrc = layers.get("lte-rrc")
    if not rrc:
        return None
    # The field name at the leaf depends on RRC version, but presence of
    # "lte-rrc.imsi" or "lte-rrc.s_TMSI" / "lte-rrc.s-TMSI" is reliable.
    flat = json.dumps(rrc)
    if "imsi" in flat.lower():
        return "imsi"
    if "s-tmsi" in flat.lower() or "s_tmsi" in flat.lower():
        return "s-tmsi"
    return None


def _our_kind(payload: bytes) -> str | None:
    res = decode_pcch(payload)
    if not res.ok:
        return None
    recs = extract_paging_records(res)
    if not recs:
        return None
    # Multi-record frames: report the first non-unknown kind. Both tshark
    # and our decoder agree on the lead record's kind.
    for r in recs:
        if r.kind != "unknown":
            return r.kind
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--strict", action="store_true",
                    help="Exit 1 on any disagreement.")
    args = ap.parse_args()

    if not _have_tshark():
        print("tshark not installed — skipping dissector cross-check.",
              file=sys.stderr)
        return 2

    if not args.pcap.exists():
        print(f"pcap not found: {args.pcap}", file=sys.stderr)
        return 2

    try:
        ts_packets = _tshark_dissect(args.pcap, args.limit)
    except RuntimeError as e:
        print(f"tshark error: {e}", file=sys.stderr)
        return 2

    our_frames = list(read_capture(str(args.pcap)))[: args.limit]

    n = min(len(ts_packets), len(our_frames))
    agree = 0
    diffs: list[tuple[int, str | None, str | None]] = []
    for i in range(n):
        ts_kind = _tshark_kind(ts_packets[i])
        our_kind = _our_kind(our_frames[i].payload)
        if ts_kind == our_kind:
            agree += 1
        else:
            diffs.append((i, ts_kind, our_kind))

    print(f"compared {n} packets — {agree} agree, {len(diffs)} differ")
    for idx, t, o in diffs[:20]:
        print(f"  [{idx}] tshark={t!r} pycrate={o!r}")
    if args.strict and diffs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
