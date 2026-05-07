"""Scanner state-machine tests with a stub dwell function."""

from __future__ import annotations

from srslte_sniffer.scanner import (CellObservation, ScanPlan, Scanner,
                                    earfcn_to_hz, hz_to_earfcn)


def test_earfcn_band3():
    # Band 3 DL: F = 1805 + 0.1 * (n - 1200) MHz
    # EARFCN 1600 → 1845 MHz, EARFCN 1300 → 1815 MHz (the legacy frequencies)
    assert earfcn_to_hz(1600) == 1_845_000_000
    assert earfcn_to_hz(1300) == 1_815_000_000


def test_legacy_frequencies_map_to_band3():
    n1 = hz_to_earfcn(1_845_000_000)
    n2 = hz_to_earfcn(1_815_000_000)
    assert n1 is not None and 1200 <= n1 <= 1949
    assert n2 is not None and 1200 <= n2 <= 1949


def test_scanner_visits_each_earfcn_per_cycle():
    visited = []

    def fake_dwell(earfcn, hz, sec):
        visited.append(earfcn)
        return CellObservation(earfcn=earfcn, hz=hz, locked=True,
                               cell_id=1, plmn="525-05")

    plan = ScanPlan(earfcns=[1450, 1750], dwell_seconds=0.0, max_cycles=2)
    obs = list(Scanner(plan, fake_dwell).run())
    assert visited == [1450, 1750, 1450, 1750]
    assert all(o.locked for o in obs)


def test_scanner_handles_unknown_earfcn():
    def fake_dwell(*args):
        raise AssertionError("should not be called for unknown EARFCN")

    plan = ScanPlan(earfcns=[999999999], dwell_seconds=0.0, max_cycles=1)
    obs = list(Scanner(plan, fake_dwell).run())
    assert len(obs) == 1
    assert obs[0].locked is False
    assert obs[0].error == "unknown EARFCN"


def test_legacy_plan():
    plan = ScanPlan.from_legacy(max_cycles=1)
    assert len(plan.earfcns) == 2
