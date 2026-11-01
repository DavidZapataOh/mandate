import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

TAG = "v0.1.0-alpha.14"
FIXTURE_PORT = 4000


def require_tlsn():
    tlsn_dir = os.environ.get("TLSN_DIR", "")
    if not tlsn_dir:
        pytest.skip("live: set TLSN_DIR to a tlsn checkout")
    if shutil.which("cargo") is None:
        pytest.skip("live: cargo not found")
    tag = subprocess.run(  # noqa: S603
        ["git", "-C", tlsn_dir, "describe", "--tags", "--exact-match"],  # noqa: S607
        capture_output=True,
        text=True,
    ).stdout.strip()
    if tag != TAG:
        pytest.fail(f"live: TLSN_DIR tag {tag!r} != {TAG}")
    return Path(tlsn_dir)


def test_live_gate_skips(monkeypatch):
    monkeypatch.delenv("TLSN_DIR", raising=False)
    with pytest.raises(pytest.skip.Exception, match="set TLSN_DIR"):
        require_tlsn()
    monkeypatch.setenv("TLSN_DIR", "/tmp/does-not-matter")  # noqa: S108
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(pytest.skip.Exception, match="cargo not found"):
        require_tlsn()


def _wait_for_port(timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", FIXTURE_PORT), timeout=2).close()
            return
        except OSError:
            time.sleep(1)
    pytest.fail("live: fixture never listened")


@pytest.mark.live
def test_zktls_proof_verifies():
    tlsn_dir = require_tlsn()
    fixture = subprocess.Popen(  # noqa: S603
        ["cargo", "run", "--release", "--bin", "tlsn-server-fixture"],  # noqa: S607
        cwd=tlsn_dir,
        env={**os.environ, "PORT": str(FIXTURE_PORT)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port()
        env = {**os.environ, "SERVER_PORT": str(FIXTURE_PORT)}
        prove = subprocess.run(  # noqa: S603
            ["cargo", "run", "--release", "--example", "attestation_prove"],  # noqa: S607
            cwd=tlsn_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        assert prove.returncode == 0, prove.stderr[-2000:]
        assert "Notarization completed successfully!" in prove.stdout
        present = subprocess.run(  # noqa: S603
            ["cargo", "run", "--release", "--example", "attestation_present"],  # noqa: S607
            cwd=tlsn_dir,
            capture_output=True,
            text=True,
        )
        assert present.returncode == 0, present.stderr[-2000:]
        assert "Presentation built successfully!" in present.stdout
        verify = subprocess.run(  # noqa: S603
            ["cargo", "run", "--release", "--example", "attestation_verify"],  # noqa: S607
            cwd=tlsn_dir,
            capture_output=True,
            text=True,
        )
        assert verify.returncode == 0, verify.stderr[-2000:]
        assert "Successfully verified" in verify.stdout
        assert "John Doe" in verify.stdout
        artifacts = list(tlsn_dir.rglob("example-json.presentation.tlsn"))
        assert artifacts and all(a.stat().st_size > 0 for a in artifacts)
    finally:
        fixture.kill()
