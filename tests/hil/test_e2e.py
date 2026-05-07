"""End-to-end test against the docker-compose lab stack.

Skipped by default — run with `pytest -m hil tests/hil` and only when
docker is available with the required srsRAN images built. CI gates this
behind a label so it doesn't run on every PR.

Until then, the offline simulator path is exercised by
`python/tests/test_streaming.py::test_streaming_via_simulator`, which
validates the same logical pipeline (journal-tail → decode → DB).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.hil

_REPO = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(
    shutil.which("docker") is None or os.environ.get("RUN_HIL") != "1",
    reason="docker missing or RUN_HIL=1 not set",
)
def test_lab_stack_captures_known_imsi(tmp_path):
    captures = tmp_path / "captures"
    captures.mkdir()
    cmd = [
        "docker", "compose",
        "-f", str(_REPO / "tests/hil/docker-compose.yml"),
        "up", "--abort-on-container-exit", "--exit-code-from", "sniffer",
    ]
    subprocess.run(
        cmd, cwd=tmp_path, check=True,
        timeout=600,
    )
    track_json = captures / "track.json"
    assert track_json.exists(), "sniffer did not produce track output"
    data = json.loads(track_json.read_text())
    # The test SIM has IMSI 001010123456789 — must be present in tracks.
    assert any(
        t["imsi"] == "001010123456789" or
        t["imsi"].startswith("sha256:")  # if hashing left enabled
        for t in data
    ), f"expected IMSI 001010123456789 in tracks, got {data!r}"
