"""Journal write/replay round-trip + torn-write tolerance."""

from __future__ import annotations

from pathlib import Path

from srslte_sniffer.journal import (KIND_PCCH, KIND_SIB1, Journal, replay)


def test_roundtrip(tmp_path: Path):
    p = tmp_path / "j"
    with Journal(p) as j:
        j.write(b"hello", kind=KIND_PCCH, ts_us=1000)
        j.write(b"world!!", kind=KIND_SIB1, ts_us=2000)
    out = list(replay(p))
    assert out == [(KIND_PCCH, 1000, b"hello"),
                   (KIND_SIB1, 2000, b"world!!")]


def test_torn_write_tolerated(tmp_path: Path):
    p = tmp_path / "j"
    with Journal(p) as j:
        j.write(b"abc", kind=KIND_PCCH, ts_us=1000)
        j.write(b"defgh", kind=KIND_PCCH, ts_us=2000)
    # Truncate the last record mid-payload.
    raw = p.read_bytes()
    p.write_bytes(raw[:-2])
    out = list(replay(p))
    # First record survives, second torn one is silently dropped.
    assert len(out) == 1
    assert out[0] == (KIND_PCCH, 1000, b"abc")


def test_replay_missing_file(tmp_path: Path):
    out = list(replay(tmp_path / "nope"))
    assert out == []
