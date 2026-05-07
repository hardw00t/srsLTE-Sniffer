"""Pytest fixtures and shared paths."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PY_ROOT = ROOT / "python"

# Allow `import srslte_sniffer` without an editable install.
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

DEMO_TXT = ROOT / "imsi_pcap_demo.txt"
DEMO_PCAP_LEGACY = ROOT / "Output Files" / "imsi.pcap"


import pytest


@pytest.fixture(scope="session")
def demo_txt() -> Path:
    if not DEMO_TXT.exists():
        pytest.skip("demo txt missing")
    return DEMO_TXT


@pytest.fixture(scope="session")
def demo_pcap() -> Path:
    if not DEMO_PCAP_LEGACY.exists():
        pytest.skip("demo pcap missing")
    return DEMO_PCAP_LEGACY
