"""Per-generation rogue rule tests."""

from __future__ import annotations

from srslte_sniffer.rogue_detector import (
    GsmCellSnapshot,
    NRCellSnapshot,
    UmtsCellSnapshot,
    detect_a5_0_announcement,
    detect_gsm_loc_update_storm,
    detect_nr_aka_failure_storm,
    detect_nr_suci_replay,
    detect_umts_downgrade_signal,
    detect_umts_reject_storm,
)


def test_a5_0_fires_on_unencrypted_cell():
    cells = [
        GsmCellSnapshot(cell_id=1, arfcn=947, cipher_mode="A5/1"),
        GsmCellSnapshot(cell_id=2, arfcn=949, cipher_mode="A5/0"),
    ]
    out = detect_a5_0_announcement(cells)
    assert len(out) == 1
    assert out[0].cell_id == 2
    assert out[0].rule == "gsm_a5_0_announced"
    assert out[0].severity == "high"


def test_gsm_loc_update_storm_threshold():
    cells = [
        GsmCellSnapshot(cell_id=1, arfcn=947, cipher_mode="A5/1",
                        location_updates_per_min=10.0),
        GsmCellSnapshot(cell_id=2, arfcn=949, cipher_mode="A5/1",
                        location_updates_per_min=42.0),
    ]
    out = detect_gsm_loc_update_storm(cells, threshold_per_min=30.0)
    assert len(out) == 1
    assert out[0].cell_id == 2


def test_umts_downgrade_signal():
    cells = [
        UmtsCellSnapshot(cell_id=1, plmn="525-05",
                         advertises_rel99_only=True),
        UmtsCellSnapshot(cell_id=2, plmn="525-05",
                         advertises_rel99_only=False),
    ]
    out = detect_umts_downgrade_signal(cells)
    assert [a.cell_id for a in out] == [1]


def test_umts_reject_storm():
    cells = [
        UmtsCellSnapshot(cell_id=1, plmn="525-05",
                         rrc_reject_per_min=200.0),
        UmtsCellSnapshot(cell_id=2, plmn="525-05",
                         rrc_reject_per_min=10.0),
    ]
    out = detect_umts_reject_storm(cells)
    assert len(out) == 1
    assert out[0].cell_id == 1


def test_nr_suci_replay():
    cells = [
        NRCellSnapshot(cell_id=1, plmn="525-05",
                       suci_replays_per_min=10.0),
        NRCellSnapshot(cell_id=2, plmn="525-05",
                       suci_replays_per_min=0.0),
    ]
    out = detect_nr_suci_replay(cells)
    assert [a.cell_id for a in out] == [1]


def test_nr_aka_failure_storm():
    cells = [
        NRCellSnapshot(cell_id=1, plmn="525-05",
                       aka_failures_per_min=20.0),
        NRCellSnapshot(cell_id=2, plmn="525-05",
                       aka_failures_per_min=0.0),
    ]
    out = detect_nr_aka_failure_storm(cells)
    assert [a.cell_id for a in out] == [1]
