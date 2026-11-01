import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from zk.settle import CIRCUIT_ID, settle

PROOF = bytes(range(256))
VK = bytes(reversed(range(256)))


def test_settlement_recorded():
    s = settle("rcpt:A-991", PROOF, VK, 1800000300)
    assert s.receipt_ref == "rcpt:A-991"
    assert s.circuit == CIRCUIT_ID == "threshold/v1"
    assert s.proof_sha256 == hashlib.sha256(PROOF).hexdigest()
    assert s.vk_sha256 == hashlib.sha256(VK).hexdigest()
    assert s.settled_at == 1800000300


def test_settlement_rejects_empty():
    with pytest.raises(ValueError, match="needs proof and vk bytes"):
        settle("rcpt:A-991", b"", VK, 1800000300)
    with pytest.raises(ValueError, match="needs proof and vk bytes"):
        settle("rcpt:A-991", PROOF, b"", 1800000300)
    with pytest.raises(ValueError, match="receipt ref must be non-empty"):
        settle("", PROOF, VK, 1800000300)


def test_settlement_hash_sensitive():
    before = settle("rcpt:A-991", PROOF, VK, 1800000300)
    mutated = bytearray(PROOF)
    mutated[0] ^= 1
    after = settle("rcpt:A-991", bytes(mutated), VK, 1800000300)
    assert before.proof_sha256 != after.proof_sha256


ROOT = Path(__file__).resolve().parent.parent


def test_no_gate_zk_coupling():
    gate_code = (
        "import sys; import gate.shim; "
        "bad = [m for m in sys.modules "
        "if m == 'zk' or m.startswith('zk.')]; "
        "assert not bad, bad"
    )
    zk_code = (
        "import sys; import zk.settle; "
        "bad = [m for m in sys.modules "
        "if m == 'gate' or m.startswith('gate.')]; "
        "assert not bad, bad"
    )
    for code in (gate_code, zk_code):
        run = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        assert run.returncode == 0, run.stderr
