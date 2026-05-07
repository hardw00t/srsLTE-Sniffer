"""Property-based fuzzing for the PCCH/BCCH decoders.

Asserts the decoders never raise on adversarial input. The real-world
OTA failure rate is <0.02% on the demo capture; this guards against
crash-class bugs from inputs that don't appear in OTA traces.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from srslte_sniffer.decoder import (
    decode_bcch_dl_sch,
    decode_pcch,
    extract_paging_records,
    extract_sib1,
    extract_sib_container,
)


_BUF = st.binary(min_size=0, max_size=200)


@given(buf=_BUF)
@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_decode_pcch_never_raises(buf: bytes) -> None:
    res = decode_pcch(buf)
    assert isinstance(res.ok, bool)
    if res.ok:
        # extraction must also be crash-safe
        recs = extract_paging_records(res)
        assert isinstance(recs, list)


@given(buf=_BUF)
@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_decode_bcch_never_raises(buf: bytes) -> None:
    res = decode_bcch_dl_sch(buf)
    assert isinstance(res.ok, bool)
    if res.ok:
        # both extractors crash-safe
        s1 = extract_sib1(res)
        # may be None, that's fine
        _ = s1
        sibs = extract_sib_container(res)
        assert isinstance(sibs, list)


@given(buf=st.binary(min_size=14, max_size=14))
@settings(max_examples=100, deadline=None)
def test_decode_pcch_realistic_size(buf: bytes) -> None:
    """14 bytes is the canonical paging PDU length — concentrate fuzzing
    near the typical wire format."""
    decode_pcch(buf)  # just don't raise
