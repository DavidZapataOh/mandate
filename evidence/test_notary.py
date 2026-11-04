import os

import pytest

from evidence import notary
from evidence.conftest import NOTARY, fake_binary
from evidence.notary import (
    NotaryError,
    new_notary_key,
    notary_public_key,
    start_notary,
)

SEED7 = bytes([7]) * 32


def test_notary_key_matches_the_rust_notary():
    assert notary_public_key(SEED7) == NOTARY
    key = new_notary_key()
    assert len(key) == 32
    assert notary_public_key(key) != NOTARY


def _notary_script(key_hex):
    return (
        "import json, sys, time\n"
        "path = sys.argv[sys.argv.index('--key-file') + 1]\n"
        "assert open(path).read() == " + repr(key_hex) + "\n"
        "print(json.dumps({'listening': sys.argv[3], 'notary_key': "
        + repr(NOTARY)
        + "}), flush=True)\n"
        "time.sleep(30)"
    )


def test_start_notary_checks_the_key_and_drops_the_file(tmp_path):
    binary = fake_binary(tmp_path, _notary_script(SEED7.hex()))
    running = start_notary(binary, SEED7, "127.0.0.1:7999")
    try:
        assert (running.address, running.public_key) == ("127.0.0.1:7999", NOTARY)
        key_file = running.process.args[-1]
        assert not os.path.exists(key_file)
    finally:
        running.stop()


def test_start_notary_refusals(tmp_path, monkeypatch):
    other = new_notary_key()
    with pytest.raises(NotaryError, match="^notary: key mismatch$"):
        start_notary(fake_binary(tmp_path, _notary_script(other.hex())), other)
    monkeypatch.setattr(notary, "START_TIMEOUT_S", 0.2)
    silent = fake_binary(tmp_path, "import time\ntime.sleep(5)")
    with pytest.raises(NotaryError, match="^notary: did not start$"):
        start_notary(silent, SEED7)
