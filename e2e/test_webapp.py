import os
import shutil
import subprocess
from pathlib import Path

import pytest

SUITE = Path(__file__).resolve().parent.parent / "webapp" / "test_app.mjs"


def _node_major():
    node = shutil.which("node")
    if node is None:
        return 0
    out = subprocess.run(  # noqa: S603
        [node, "--version"], capture_output=True, text=True, check=True
    ).stdout
    return int(out.strip().lstrip("v").split(".")[0])


def test_webapp_suite_against_the_desk(running_desk, pairing_token):
    if _node_major() < 22:
        pytest.skip("webapp: needs node >= 22 (WebCrypto Ed25519)")
    desk, url = running_desk
    desk.quote("acme-991", 20000, "USD", "A-991")
    run = subprocess.run(  # noqa: S603
        ["node", "--test", "--test-reporter=tap", str(SUITE)],  # noqa: S607
        env={**os.environ, "MANDATE_URL": url, "MANDATE_PAIR": pairing_token},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert run.returncode == 0, run.stdout[-3000:] + run.stderr[-2000:]
    assert "# skipped 0" in run.stdout
    assert desk.status("q:000001")["status"] == "approved"
    assert len(desk.holder_keys) == 1
    assert desk.confirm("q:000001")["status"] == "confirmed"
