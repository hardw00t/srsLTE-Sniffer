"""Adapter that consumes ``grgsm_livemon`` GSMTAP-over-UDP output and
writes records into our journal + DB.

``grgsm_livemon`` is the realtime GSM downlink decoder shipped with
gr-gsm. It opens a configurable downlink ARFCN, demodulates, and emits
GSMTAP UDP packets on localhost:4729. Pointing this adapter at that port
is the cheapest way to get end-to-end 2G captures into our pipeline.

Run:
    grgsm_livemon --args="..." -f 947600000 &
    srslte-sniffer gsm-adapter --port 4729 --db captures.db

The adapter:
    1. Listens on UDP/4729 for GSMTAP packets.
    2. Filters to PCH (paging channel) downlink frames.
    3. Strips the GSMTAP header.
    4. Decodes the L3 RR Paging Request via decoder_2g.
    5. Writes to journal + DB tagged radio_type='2g'.

The realtime PHY work is entirely upstream (gr-gsm); this module is the
~150-LOC adapter glue.
"""

from __future__ import annotations

import asyncio
import dataclasses
import socket

from .db import CaptureDB
from .decoder_2g import decode_paging, extract_records
from .gsmtap import (
    GSMTAP_CHAN_PCH,
    GSMTAP_TYPE_UM,
    parse_header,
)
from .journal import KIND_PCCH, Journal


@dataclasses.dataclass
class GSMAdapterStats:
    received: int = 0
    pch_frames: int = 0
    decoded: int = 0
    failed: int = 0
    inserted: int = 0


def _is_pch(hdr: dict) -> bool:
    return (hdr.get("type") == GSMTAP_TYPE_UM
            and hdr.get("sub_type") == GSMTAP_CHAN_PCH)


def consume_one(buf: bytes,
                *, db: CaptureDB | None = None,
                journal: Journal | None = None,
                stats: GSMAdapterStats | None = None) -> None:
    """Process a single UDP datagram from grgsm_livemon. Best-effort —
    silently drops malformed input."""
    if stats is not None:
        stats.received += 1
    hdr = parse_header(buf)
    if not hdr:
        return
    if not _is_pch(hdr):
        return
    payload = buf[16:]
    if stats is not None:
        stats.pch_frames += 1

    res = decode_paging(payload)
    if not res.ok:
        if stats is not None:
            stats.failed += 1
        return
    if stats is not None:
        stats.decoded += 1

    if journal is not None:
        journal.write(payload, kind=KIND_PCCH, fsync=False)

    if db is not None:
        for w in extract_records(res):
            db.insert_wide_paging(
                w, arfcn=hdr.get("arfcn"),
                raw_hex=payload.hex(),
            )
            stats and setattr(stats, "inserted", stats.inserted + 1)


async def run_udp_consumer(
    *,
    port: int = 4729,
    db_path: str | None = None,
    journal_path: str | None = None,
    bind_host: str = "127.0.0.1",
    stop_event: asyncio.Event | None = None,
) -> GSMAdapterStats:
    """Long-running UDP consumer loop. Returns when ``stop_event`` is set
    or the loop is cancelled."""
    stats = GSMAdapterStats()
    db = CaptureDB(db_path) if db_path else None
    journal = Journal(journal_path) if journal_path else None

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind((bind_host, port))

    try:
        while not (stop_event and stop_event.is_set()):
            try:
                data, _addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096), timeout=0.5,
                )
            except asyncio.TimeoutError:
                continue
            consume_one(data, db=db, journal=journal, stats=stats)
    finally:
        sock.close()
        if db:
            db.close()
        if journal:
            journal.close()
    return stats


# Synchronous helper for tests / one-shot consumption of a fixture.
def consume_bytes(packets: list[bytes],
                  *, db_path: str | None = None) -> GSMAdapterStats:
    stats = GSMAdapterStats()
    db = CaptureDB(db_path) if db_path else None
    try:
        for p in packets:
            consume_one(p, db=db, stats=stats)
    finally:
        if db:
            db.close()
    return stats
