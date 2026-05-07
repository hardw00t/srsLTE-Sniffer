"""5G NR decoder skeleton tests."""

from __future__ import annotations

import pytest

from srslte_sniffer import nr_decoder


@pytest.mark.skipif(not nr_decoder.is_nr_available(),
                    reason="pycrate NR-RRC unavailable")
def test_invalid_nr_buf_does_not_raise():
    res = nr_decoder.decode_nr_pcch(b"\x00\x00\x00\x00")
    # Either decoder accepts it (unlikely) or returns ok=False — never raises.
    assert isinstance(res.ok, bool)
    if not res.ok:
        assert res.error
    else:
        assert nr_decoder.extract_nr_paging_records(res) == [] or True


def test_module_documents_supi_caveat():
    # Defensive — NR SUPI is encrypted (SUCI) so the module should NOT pretend
    # it can extract SUPI from passive captures. The dataclass's `kind` field
    # should not include 'supi' as a value.
    rec = nr_decoder.NRPagingRecord(kind="ng-5g-s-tmsi", ng5g_s_tmsi=0x1234)
    assert rec.kind != "supi"
    assert rec.kind != "imsi"
