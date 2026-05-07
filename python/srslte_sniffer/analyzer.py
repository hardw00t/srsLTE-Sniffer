"""End-to-end pipeline: capture file → decoded records → DB.

This is the offline replacement for the `convert_to_csv.c` step in
`loop_catcher.sh`. It replaces the brittle hex-pattern parser with the
ASN.1-based decoder and writes a SQLite store alongside (or instead of) the
CSV.
"""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Iterable
from pathlib import Path

from .db import CaptureDB
from .decoder import (
    PagingRecord,
    decode_bcch_dl_sch,
    decode_pcch,
    extract_paging_records,
    extract_sib1,
    extract_sib_container,
)
from .pcap_io import CapturedFrame, read_capture


@dataclasses.dataclass
class AnalyzeStats:
    frames: int = 0
    decoded_pcch: int = 0
    decoded_sib1: int = 0
    decoded_sib_other: int = 0
    failed: int = 0
    pagings_total: int = 0
    pagings_imsi: int = 0
    pagings_stmsi: int = 0
    pagings_unknown: int = 0
    multi_record_frames: int = 0


def analyze_frames(
    frames: Iterable[CapturedFrame],
    db: CaptureDB | None = None,
    *,
    earfcn: int | None = None,
    cell_id: int | None = None,
    hash_identifiers: bool = True,
) -> AnalyzeStats:
    """Iterate frames, decode each, optionally insert into a DB."""
    stats = AnalyzeStats()
    for frame in frames:
        stats.frames += 1
        framing = frame.framing
        ts = frame.timestamp_us

        if framing == "pcch":
            res = decode_pcch(frame.payload)
            if not res.ok:
                stats.failed += 1
                continue
            stats.decoded_pcch += 1
            recs = extract_paging_records(res)
            if len(recs) > 1:
                stats.multi_record_frames += 1
            for r in recs:
                stats.pagings_total += 1
                if r.kind == "imsi":
                    stats.pagings_imsi += 1
                elif r.kind == "s-tmsi":
                    stats.pagings_stmsi += 1
                else:
                    stats.pagings_unknown += 1
                if db is not None:
                    to_store: PagingRecord = r.hashed() if hash_identifiers else r
                    db.insert_paging(
                        to_store,
                        ts_us=ts,
                        earfcn=earfcn,
                        cell_id=cell_id,
                        raw_hex=frame.payload.hex(),
                    )

        elif framing == "sib1":
            res = decode_bcch_dl_sch(frame.payload)
            if not res.ok:
                stats.failed += 1
                continue
            sib1 = extract_sib1(res)
            if sib1:
                stats.decoded_sib1 += 1
                if db is not None:
                    db.insert_cell(
                        sib1,
                        earfcn=earfcn,
                        cell_id=cell_id,
                        raw_hex=frame.payload.hex(),
                        ts_us=ts,
                    )

        elif framing == "sib2":
            res = decode_bcch_dl_sch(frame.payload)
            if not res.ok:
                stats.failed += 1
                continue
            sibs = extract_sib_container(res)
            for sib in sibs:
                stats.decoded_sib_other += 1
                if db is not None:
                    db.insert_sib(
                        sib.sib_type,
                        earfcn=earfcn,
                        cell_id=cell_id,
                        raw_hex=frame.payload.hex(),
                        ts_us=ts,
                    )

        else:
            # Unknown framing — try PCCH first, else give up.
            res = decode_pcch(frame.payload)
            if res.ok:
                stats.decoded_pcch += 1
                for r in extract_paging_records(res):
                    stats.pagings_total += 1
                    if db is not None:
                        db.insert_paging(
                            r.hashed() if hash_identifiers else r,
                            ts_us=ts, earfcn=earfcn, cell_id=cell_id,
                            raw_hex=frame.payload.hex(),
                        )
            else:
                stats.failed += 1

    return stats


def analyze_file(
    path: str | Path,
    db_path: str | Path | None = None,
    *,
    earfcn: int | None = None,
    cell_id: int | None = None,
    hash_identifiers: bool = True,
) -> AnalyzeStats:
    """Convenience: open a capture file and run the pipeline."""
    db = CaptureDB(db_path) if db_path else None
    try:
        with (db.transaction() if db else _nullctx()):
            return analyze_frames(
                read_capture(path),
                db=db,
                earfcn=earfcn,
                cell_id=cell_id,
                hash_identifiers=hash_identifiers,
            )
    finally:
        if db:
            db.close()


@contextlib.contextmanager
def _nullctx():
    yield
