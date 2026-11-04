import json
import os
import time

import pytest

from bank.credentials import BANK_KEY_ENV, HOLDER_KEY_ENV
from bank.increase import IncreaseRail, sandbox_client
from evidence.notary import new_notary_key, start_notary
from evidence.zktls import BankProofSetup, find_verifier
from swarm.conftest import DEMO_INTENT
from swarm.console_line import console_line_json
from swarm.holder_proof import prove_presentation


def _binary():
    binary = find_verifier(os.environ)
    if binary is None:
        pytest.skip("live: set MANDATE_ZKTLS_BIN to a built mandate-zktls")
    for name in (BANK_KEY_ENV, HOLDER_KEY_ENV):
        if not os.environ.get(name):
            pytest.skip(f"live: set {name}")
    return binary


@pytest.fixture
def live_desk(make_desk):
    binary = _binary()
    rail = IncreaseRail.connect(sandbox_client(os.environ[BANK_KEY_ENV]))
    notary = start_notary(binary, new_notary_key(), "127.0.0.1:7049")
    setup = BankProofSetup(
        binary,
        notary.address,
        notary.public_key,
        {"checking-881": rail.account_id("checking-881")},
    )
    lines = []
    desk, _ = make_desk(
        clock=lambda: int(time.time()),
        bank=rail,
        intents=(DEMO_INTENT,),
        publish=lines.append,
        zktls=setup,
    )
    yield desk, binary, lines
    notary.stop()


def _presentation(desk, binary):
    challenge = desk.funds_challenge("i:000001")
    assert challenge["status"] == "open", challenge
    holder_env = {k: v for k, v in os.environ.items() if k != BANK_KEY_ENV}
    return prove_presentation(binary, challenge, holder_env)


@pytest.mark.live
def test_holder_proves_the_sandbox_balance(live_desk):
    desk, binary, lines = live_desk
    proven = desk.record_funds_proof("i:000001", _presentation(desk, binary))
    assert proven["status"] == "proven", proven
    assert proven["server"] == "sandbox.increase.com"
    assert desk.intent_receipt("i:000001")["evidence_ref"] == proven["evidence_ref"]
    seen = [console_line_json(line) for line in lines]
    seen.append(json.dumps(desk.intent_receipt("i:000001")))
    key = os.environ[HOLDER_KEY_ENV]
    assert all(key not in text for text in seen)


@pytest.mark.live
def test_a_tampered_presentation_is_refused_by_the_real_verifier(live_desk):
    desk, binary, _ = live_desk
    tampered = bytearray(_presentation(desk, binary))
    tampered[len(tampered) // 2] ^= 1
    assert desk.record_funds_proof("i:000001", bytes(tampered)) == {
        "status": "denied",
        "intent_id": "i:000001",
        "reason": "zktls: presentation invalid",
    }
