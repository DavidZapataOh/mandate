import shutil
import subprocess
from pathlib import Path

import pytest

CIRCUIT = Path(__file__).resolve().parent / "threshold"


def require_zk():
    if shutil.which("nargo") is None:
        pytest.skip("live: nargo not found")
    if shutil.which("bb") is None:
        pytest.skip("live: bb not found")
    try:
        done = subprocess.run(  # noqa: S603
            ["nargo", "--version"],  # noqa: S607
            capture_output=True,
            text=True,
        )
    except Exception:
        pytest.skip("live: cannot verify nargo version")
    if done.returncode != 0:
        pytest.skip("live: cannot verify nargo version")
    line = done.stdout.splitlines()[0].strip() if done.stdout.strip() else ""
    parts = line.split("nargo version = ", 1)
    token = parts[1].strip() if len(parts) > 1 else line
    if "-beta" in token:
        pytest.skip(
            f"live: nargo {token} emits legacy artifacts bb cannot read; "
            "align to nargo 1.0.0-rc.4 + bb 5.0.1"
        )


def test_zk_gate_skips(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(pytest.skip.Exception, match="nargo not found"):
        require_zk()
    monkeypatch.setattr(
        shutil, "which", lambda name: "/bin/nargo" if name == "nargo" else None
    )
    with pytest.raises(pytest.skip.Exception, match="bb not found"):
        require_zk()


def test_zk_gate_skips_beta_nargo(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: "/bin/tool")

    def fake_run(stdout, returncode=0):
        def run(_args, **_kwargs):
            return subprocess.CompletedProcess(
                _args, returncode, stdout=stdout, stderr=""
            )

        return run

    beta = "nargo version = 1.0.0-beta.9\nnoirc version = 1.0.0-beta.9\n"
    monkeypatch.setattr(subprocess, "run", fake_run(beta))
    with pytest.raises(pytest.skip.Exception, match="legacy artifacts"):
        require_zk()
    rc = "nargo version = 1.0.0-rc.4\nnoirc version = 1.0.0-rc.4\n"
    monkeypatch.setattr(subprocess, "run", fake_run(rc))
    require_zk()
    final = "nargo version = 1.0.0\nnoirc version = 1.0.0\n"
    monkeypatch.setattr(subprocess, "run", fake_run(final))
    require_zk()
    monkeypatch.setattr(subprocess, "run", fake_run("", returncode=1))
    with pytest.raises(pytest.skip.Exception, match="cannot verify"):
        require_zk()


def _run(args):
    done = subprocess.run(  # noqa: S603
        args, cwd=CIRCUIT, capture_output=True, text=True
    )
    return done.returncode, done.stdout, done.stderr[-2000:]


@pytest.mark.live
def test_circuit_verifies():
    require_zk()
    code, _out, err = _run(["nargo", "test"])
    assert code == 0, err
    code, _out, err = _run(["nargo", "compile"])
    assert code == 0, err
    code, _out, err = _run(["nargo", "execute"])
    assert code == 0, err
    code, _out, err = _run(
        ["bb", "write_vk", "-b", "./target/threshold.json", "-o", "./target"]
    )
    assert code == 0, err
    code, _out, err = _run(
        [
            "bb",
            "prove",
            "-b",
            "./target/threshold.json",
            "-w",
            "./target/threshold.gz",
            "-k",
            "./target/vk",
            "-o",
            "./target",
        ]
    )
    assert code == 0, err
    proof = CIRCUIT / "target" / "proof"
    assert proof.stat().st_size > 0
    code, _out, err = _run(
        ["bb", "verify", "-p", "./target/proof", "-k", "./target/vk"]
    )
    assert code == 0, err
    tampered = CIRCUIT / "target" / "proof-tampered"
    raw = bytearray(proof.read_bytes())
    raw[len(raw) // 2] ^= 1
    tampered.write_bytes(bytes(raw))
    code, _out, _err = _run(
        ["bb", "verify", "-p", "./target/proof-tampered", "-k", "./target/vk"]
    )
    assert code != 0
