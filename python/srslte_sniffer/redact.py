"""PCAP redaction.

Re-write a capture so that IMSI / M-TMSI values are replaced with
**deterministic hash-derived placeholders** rather than original values.
The output is wire-format-valid (re-encoded UPER) so Wireshark dissects it
exactly like a real capture, and the same input always produces the same
redacted output (so multiple captures of the same subscriber correlate
across redacted exports — useful for sharing).

Caveats:
- Only paging-channel records are touched. SIB1/SIB2 don't carry
  identifiers so they pass through unchanged.
- IMSI MCC is preserved — required to keep network-shape information
  meaningful. Only MNC + MSIN are replaced. To redact MCC too, pass
  ``preserve_mcc=False``.
- Unknown / undecodable PDUs are passed through unmodified, with their
  count returned in the stats dict so the operator can decide if that's
  acceptable.
"""

from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Iterable
from pathlib import Path

from .decoder import _PCCH, decode_pcch  # noqa: F401 — _PCCH used directly
from .pcap_io import (
    PAGING_HEADER,
    SIB1_HEADER,
    SIB2_HEADER,
    PcapngWriter,
    classify,
    read_capture,
)


@dataclasses.dataclass
class RedactStats:
    frames_in: int = 0
    frames_out: int = 0
    pcch_redacted: int = 0
    pcch_passthrough_undecodable: int = 0
    other: int = 0


def _hashed_digits(seed: bytes, n: int) -> list[int]:
    """Deterministic 0–9 digits from a seed."""
    h = hashlib.sha256(seed).digest()
    out: list[int] = []
    i = 0
    while len(out) < n:
        out.append(h[i % len(h)] % 10)
        i += 1
    return out


def _redact_value(val: dict, *, preserve_mcc: bool) -> bool:
    """Mutate the decoded PCCH value in-place. Returns True if anything
    was redacted."""
    msg = val.get("message")
    if not msg or msg[0] != "c1":
        return False
    inner = msg[1]
    if inner[0] != "paging":
        return False
    paging = inner[1]
    touched = False
    for rec in paging.get("pagingRecordList", []) or []:
        ue_id = rec.get("ue-Identity")
        if not ue_id:
            continue
        if ue_id[0] == "imsi":
            digits = list(ue_id[1])
            seed = ("imsi:" + "".join(str(d) for d in digits)).encode()
            replacement = _hashed_digits(seed, 15)
            if preserve_mcc:
                # Keep first 3 digits (MCC), replace MNC+MSIN.
                replacement = digits[:3] + replacement[3:15]
            rec["ue-Identity"] = ("imsi", replacement)
            touched = True
        elif ue_id[0] == "s-TMSI":
            stmsi = ue_id[1]
            mmec_v, mmec_b = stmsi.get("mmec", (0, 8))
            mtmsi_v, mtmsi_b = stmsi.get("m-TMSI", (0, 32))
            seed = f"stmsi:{mmec_v}:{mtmsi_v}".encode()
            h = hashlib.sha256(seed).digest()
            new_mmec = h[0] & ((1 << mmec_b) - 1)
            new_mtmsi = (
                int.from_bytes(h[1:5], "big") & ((1 << mtmsi_b) - 1)
            )
            rec["ue-Identity"] = ("s-TMSI", {
                "mmec": (new_mmec, mmec_b),
                "m-TMSI": (new_mtmsi, mtmsi_b),
            })
            touched = True
    return touched


def redact_capture(
    src: str | Path,
    dst: str | Path,
    *,
    preserve_mcc: bool = True,
) -> RedactStats:
    """Read ``src``, redact, write to ``dst`` (pcapng)."""
    stats = RedactStats()
    with PcapngWriter(dst) as w:
        for frame in read_capture(str(src)):
            stats.frames_in += 1
            framing = frame.framing
            if framing == "pcch":
                res = decode_pcch(frame.payload)
                if not res.ok:
                    stats.pcch_passthrough_undecodable += 1
                    w.write_paging(frame.payload, frame.timestamp_us)
                    stats.frames_out += 1
                    continue
                if _redact_value(res.value, preserve_mcc=preserve_mcc):
                    stats.pcch_redacted += 1
                # Re-encode with the mutated value.
                _PCCH.set_val(res.value)
                new_payload = _PCCH.to_uper()
                w.write_paging(new_payload, frame.timestamp_us)
                stats.frames_out += 1
            elif framing == "sib1":
                w.write_sib1(frame.payload, frame.timestamp_us)
                stats.frames_out += 1
                stats.other += 1
            elif framing == "sib2":
                w.write_sib2(frame.payload, frame.timestamp_us)
                stats.frames_out += 1
                stats.other += 1
            else:
                # Unknown framing — pass through with paging headers as the
                # safe default (matches the original parse_data.c assumption).
                w.write_paging(frame.payload, frame.timestamp_us)
                stats.frames_out += 1
                stats.other += 1
    return stats


# Re-exports so the test file doesn't reach into private names.
__all__ = ["RedactStats", "redact_capture"]


# Keep imports of header constants alive for other tooling — silence
# unused-import warnings.
_ = (PAGING_HEADER, SIB1_HEADER, SIB2_HEADER, classify)
_ = Iterable  # type re-export hint
