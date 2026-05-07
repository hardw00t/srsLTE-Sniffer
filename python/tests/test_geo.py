"""GeoCache import + lookup tests."""

from __future__ import annotations

from pathlib import Path

from srslte_sniffer.geo import GeoCache


SAMPLE_CSV = """\
radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal
LTE,525,5,2001,42,0,103.8198,1.3521,1000,1,1,1700000000,1700000001,0
LTE,525,5,2001,43,0,103.82,1.3522,1500,1,1,1700000000,1700000001,0
GSM,525,5,2001,99,0,103.83,1.36,2000,1,1,1700000000,1700000001,0
LTE,525,5,2002,9999,0,103.84,1.37,500,1,1,1700000000,1700000001,0
"""


def test_import_filters_lte_only(tmp_path: Path):
    csv = tmp_path / "ocid.csv"
    csv.write_text(SAMPLE_CSV)
    cache = GeoCache(tmp_path / "geo.db")
    try:
        n = cache.import_opencellid_csv(csv)
        assert n == 3  # GSM row skipped
        assert cache.count() == 3
    finally:
        cache.close()


def test_lookup_existing(tmp_path: Path):
    csv = tmp_path / "ocid.csv"
    csv.write_text(SAMPLE_CSV)
    cache = GeoCache(tmp_path / "geo.db")
    try:
        cache.import_opencellid_csv(csv)
        loc = cache.lookup(525, 5, 2001, 42)
        assert loc is not None
        assert abs(loc.lon - 103.8198) < 1e-6
        assert abs(loc.lat - 1.3521) < 1e-6
        assert loc.accuracy_m == 1000
    finally:
        cache.close()


def test_lookup_missing_returns_none(tmp_path: Path):
    cache = GeoCache(tmp_path / "geo.db")
    try:
        assert cache.lookup(999, 999, 999, 999) is None
    finally:
        cache.close()


def test_invalid_csv_raises(tmp_path: Path):
    bad = tmp_path / "bad.csv"
    bad.write_text("foo,bar,baz\n1,2,3\n")
    cache = GeoCache(tmp_path / "geo.db")
    try:
        import pytest
        with pytest.raises(ValueError):
            cache.import_opencellid_csv(bad)
    finally:
        cache.close()
