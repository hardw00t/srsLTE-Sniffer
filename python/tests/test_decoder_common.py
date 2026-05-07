"""WidePagingRecord smoke tests."""

from __future__ import annotations

from srslte_sniffer.decoder_common import ALL_RADIO_TYPES, WidePagingRecord


def test_radio_types_complete():
    assert set(ALL_RADIO_TYPES) == {"2g", "3g", "4g", "5g-nsa", "5g-sa"}


def test_primary_tmsi_picks_first_non_none():
    w = WidePagingRecord(radio_type="3g", kind="p-tmsi", p_tmsi=42)
    assert w.primary_tmsi == 42

    w2 = WidePagingRecord(radio_type="4g", kind="s-tmsi", m_tmsi=99)
    assert w2.primary_tmsi == 99

    w3 = WidePagingRecord(radio_type="5g-sa", kind="ng-5g-s-tmsi",
                          ng_5g_s_tmsi=0xABCDEF)
    assert w3.primary_tmsi == 0xABCDEF


def test_primary_tmsi_none_for_imsi_only():
    w = WidePagingRecord(radio_type="2g", kind="imsi", imsi="525058131997813")
    assert w.primary_tmsi is None
