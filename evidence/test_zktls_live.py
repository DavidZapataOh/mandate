import os
import subprocess
import time

import pytest

from bank.credentials import BANK_KEY_ENV
from bank.increase import sandbox_client
from evidence.notary import new_notary_key, start_notary
from evidence.zktls import check_balance, find_verifier, run_verifier

HOLDER_KEY_ENV = "INCREASE_HOLDER_API_KEY"
NONCE = "a7a12d73de0370d60b0ea24041a748ee6fc4db6974cf47b3b502f2c7d52b3ed8"


def _binary():
    binary = find_verifier(os.environ)
    if binary is None:
        pytest.skip("live: set MANDATE_ZKTLS_BIN to a built mandate-zktls")
    return binary


def _account_id():
    for name in (BANK_KEY_ENV, HOLDER_KEY_ENV):
        if not os.environ.get(name):
            pytest.skip(f"live: set {name}")
    client = sandbox_client(os.environ[BANK_KEY_ENV])
    for account in client.accounts.list():
        if account.status == "open":
            return account.id
    pytest.skip("live: no open sandbox account")


@pytest.mark.live
def test_real_notary_and_prover_round_trip(tmp_path):
    binary = _binary()
    account_id = _account_id()
    holder_key = os.environ[HOLDER_KEY_ENV]
    notary = start_notary(binary, new_notary_key(), "127.0.0.1:7047")
    out = tmp_path / "p.tlsn"
    try:
        run = subprocess.run(  # noqa: S603
            [
                binary, "prove", "--notary", notary.address,
                "--host", "sandbox.increase.com",
                "--path", f"/accounts/{account_id}/balance",
                "--nonce", NONCE, "--reveal", "account_id,available_balance",
                "--auth-env", HOLDER_KEY_ENV, "--out", str(out),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )  # fmt: skip
    finally:
        notary.stop()
    assert run.returncode == 0, run.stdout
    presentation = out.read_bytes()
    assert holder_key.encode() not in presentation
    assert holder_key not in run.stdout + run.stderr
    disclosed = run_verifier(binary, presentation)
    assert disclosed.server_name == "sandbox.increase.com"
    assert disclosed.notary_key == notary.public_key
    assert abs(disclosed.time - time.time()) < 120
    assert f"\r\nmandate-nonce: {NONCE}\r\n" in disclosed.sent
    assert "\r\nauthorization: \x00" in disclosed.sent
    assert holder_key not in disclosed.sent + disclosed.recv
    proof = check_balance(
        disclosed,
        presentation,
        notary_key=notary.public_key,
        account_id=account_id,
        nonce=NONCE,
        now=int(time.time()),
    )
    assert proof.account_id == account_id
    assert isinstance(proof.available_balance, int)
    print(  # noqa: T201
        f"LIVE size={len(presentation)} balance_revealed=True time={disclosed.time}"
    )
