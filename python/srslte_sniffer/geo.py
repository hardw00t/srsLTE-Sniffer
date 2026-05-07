"""Cell-ID → geographic location lookup (offline OpenCellID-format CSV).

OpenCellID and Mozilla Location Service publish an LTE cell database with
columns:

    radio,mcc,net,area,cell,unit,lon,lat,range,samples,...

We don't ship that data — it's gigabytes — but we do support loading any
subset the operator pulls from https://opencellid.org/downloads.php into
a small SQLite cache for fast lookup.

The dashboard's optional `/cells/map` page consumes this — see
`docs/USAGE.md`.
"""

from __future__ import annotations

import csv
import dataclasses
import sqlite3
from pathlib import Path

CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cell_geo (
    mcc INTEGER, mnc INTEGER, tac INTEGER, cell_id INTEGER,
    lon REAL, lat REAL, accuracy_m INTEGER,
    PRIMARY KEY (mcc, mnc, tac, cell_id)
);
CREATE INDEX IF NOT EXISTS idx_geo_mccmnc ON cell_geo(mcc, mnc);
"""


@dataclasses.dataclass
class CellLocation:
    mcc: int
    mnc: int
    tac: int
    cell_id: int
    lon: float
    lat: float
    accuracy_m: int


class GeoCache:
    """Tiny SQLite cache keyed by (MCC, MNC, TAC, cell_id)."""

    def __init__(self, path: str | Path = "cell_geo.db") -> None:
        self.path = Path(path)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.executescript(CACHE_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def import_opencellid_csv(self, csv_path: str | Path) -> int:
        """Load an OpenCellID CSV. Filters to LTE rows only."""
        n = 0
        with Path(csv_path).open("r", newline="") as fh:
            reader = csv.reader(fh)
            header = next(reader, None)
            if header is None:
                return 0
            cols = {name.lower(): i for i, name in enumerate(header)}
            need = {"radio", "mcc", "net", "area", "cell", "lon", "lat", "range"}
            if not need.issubset(cols):
                raise ValueError(
                    f"unexpected CSV header — need columns: {need}, got {set(cols)}"
                )
            self._conn.execute("BEGIN")
            try:
                for row in reader:
                    if len(row) <= max(cols.values()):
                        continue
                    if row[cols["radio"]].upper() != "LTE":
                        continue
                    try:
                        self._conn.execute(
                            "INSERT OR REPLACE INTO cell_geo VALUES (?,?,?,?,?,?,?)",
                            (
                                int(row[cols["mcc"]]),
                                int(row[cols["net"]]),
                                int(row[cols["area"]]),
                                int(row[cols["cell"]]),
                                float(row[cols["lon"]]),
                                float(row[cols["lat"]]),
                                int(float(row[cols["range"]])),
                            ),
                        )
                        n += 1
                    except (ValueError, TypeError):
                        continue
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return n

    def lookup(
        self,
        mcc: int,
        mnc: int,
        tac: int,
        cell_id: int,
    ) -> CellLocation | None:
        cur = self._conn.execute(
            "SELECT lon, lat, accuracy_m FROM cell_geo "
            "WHERE mcc=? AND mnc=? AND tac=? AND cell_id=?",
            (mcc, mnc, tac, cell_id),
        )
        row = cur.fetchone()
        if not row:
            return None
        lon, lat, acc = row
        return CellLocation(mcc, mnc, tac, cell_id, lon, lat, acc)

    def count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM cell_geo")
        return int(cur.fetchone()[0])
