"""Test-only Increase transcripts and fake verifier binaries."""

import json
import stat
import sys
from pathlib import Path

from evidence.zktls import Disclosed

NOW = 1800001000
NONCE = "a7a12d73de0370d60b0ea24041a748ee6fc4db6974cf47b3b502f2c7d52b3ed8"
ACCT = "account_in71c4amph0vgo2qllky"
NOTARY = "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"
H = "\x00"


def increase_disclosed(
    balance: int = 50000, nonce: str = NONCE, time: int = NOW - 5
) -> Disclosed:
    """A verified balance lookup as the Rust verifier prints it (NUL = hidden)."""
    sent = (
        f"GET /accounts/{ACCT}/balance HTTP/1.1\r\n"
        "host: sandbox.increase.com\r\naccept: application/json\r\n"
        "accept-encoding: identity\r\nconnection: close\r\n"
        f"mandate-nonce: {nonce}\r\nauthorization: {H * 30}\r\n\r\n"
    )
    body = (
        "{\n"
        f'  "account_id": "{ACCT}",{H * 3}'
        f'  "available_balance": {balance}{H * 3}'
        f"{H * 60}}}"
    )
    recv = (
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
        f"{H * 40}\r\ncontent-length: 120\r\n\r\n{body}"
    )
    return Disclosed("sandbox.increase.com", time, NOTARY, sent, recv)


def verifier_line(disclosed: Disclosed) -> str:
    """The JSON line `mandate-zktls verify` prints for `disclosed`."""
    return json.dumps(
        {
            "ok": True,
            "server_name": disclosed.server_name,
            "time": disclosed.time,
            "notary_key": disclosed.notary_key,
            "sent": disclosed.sent,
            "recv": disclosed.recv,
        }
    )


def fake_binary(tmp_path: Path, body: str) -> str:
    """Write an executable Python script standing in for `mandate-zktls`."""
    path = tmp_path / f"mandate-zktls-{len(list(tmp_path.iterdir()))}"
    path.write_text(f"#!{sys.executable}\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def fake_verifier(tmp_path: Path, disclosed: Disclosed) -> str:
    """A verifier binary that prints `disclosed` for any presentation."""
    return fake_binary(tmp_path, f"print({verifier_line(disclosed)!r})")
