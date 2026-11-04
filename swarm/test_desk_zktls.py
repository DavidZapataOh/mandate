import json
import os
from pathlib import Path

import pytest

from bank.api import RailError
from bank.conftest import RecordingRail
from evidence.conftest import (
    ACCT,
    NONCE,
    NOTARY,
    NOW,
    fake_verifier,
    increase_disclosed,
)
from evidence.zktls import BankProofSetup
from gate.sdjwt import process
from swarm.conftest import DEMO_INTENT
from swarm.console_line import console_line_json
from swarm.receipt import RECEIPT_TYP
from swarm.test_receipt import GATE, HOLDER

PROOF = b"proof"
ZK_SHA = "c1cda26362828b69266512052b97cb3729e3b052e4ade47c0a1e3383defe73c7"
ZK_REF = "ev:zktls-attestation:c1cda26362828b69266512052b97cb37"
# The opaque intent ref of DEMO_INTENT signed by HOLDER (seed 0x02 * 32),
# derived with hashlib outside the desk; NONCE stays the intent hash.
INTENT_REF = "ev:holder-intent:47a61cf184a3576c0bb1667c96d3c2ad"
GOLDEN_ZKTLS = (
    Path(__file__).resolve().parent.parent
    / "console/src/explorer/__fixtures__/receipt-zktls.json"
)
# The same bound payment without a proof is the sandbox golden.
GOLDEN_COOP = GOLDEN_ZKTLS.with_name("receipt-sandbox.json")
COOP_REF = "ev:cooperative-signed:c97da00074742018dff37a1130a145f3"


@pytest.fixture
def zk_desk(make_desk, tmp_path):
    def build(disclosed=None, **extra):
        setup = BankProofSetup(
            fake_verifier(tmp_path, disclosed or increase_disclosed()),
            "127.0.0.1:7047",
            NOTARY,
            {"checking-881": ACCT},
        )
        return make_desk(
            clock=lambda: NOW,
            bank=RecordingRail(balance=50000),
            intents=(DEMO_INTENT,),
            zktls=setup,
            **extra,
        )

    return build


def _signed(desk, receipt):
    payload, reason = process(receipt["sd"], desk.gate_public_key, RECEIPT_TYP)
    assert reason == "ok: verified"
    return payload


def _pay(desk, holder, sign_quote, intent_id="i:000001"):
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id=intent_id)
    desk.approve(q["quote_id"], sign_quote(holder, q))
    paid = desk.confirm(q["quote_id"])
    return desk.proof_receipt(paid["payment_id"])


def test_the_challenge_names_the_one_request(zk_desk, make_desk):
    desk, _ = zk_desk()
    assert desk.funds_challenge("i:000001") == {
        "status": "open",
        "intent_id": "i:000001",
        "host": "sandbox.increase.com",
        "path": f"/accounts/{ACCT}/balance",
        "nonce": NONCE,
        "notary": "127.0.0.1:7047",
        "notary_key": NOTARY,
        "reveal": ["account_id", "available_balance"],
    }
    assert desk.funds_challenge("i:000009") == {
        "status": "unknown",
        "intent_id": "i:000009",
    }
    plain, _ = make_desk(bank=RecordingRail(balance=50000), intents=(DEMO_INTENT,))
    assert plain.funds_challenge("i:000001") == {
        "status": "unavailable",
        "intent_id": "i:000001",
        "reason": "zktls: not configured",
    }


def test_a_verified_proof_becomes_the_certified_funds_evidence(zk_desk, sign_quote):
    desk, holder = zk_desk(holder_key=HOLDER)
    assert desk.record_funds_proof("i:000001", PROOF) == {
        "status": "proven",
        "intent_id": "i:000001",
        "evidence_ref": ZK_REF,
        "server": "sandbox.increase.com",
        "session_time": NOW - 5,
    }
    assert desk.intent_receipt("i:000001")["evidence_ref"] == ZK_REF
    receipt = _pay(desk, holder, sign_quote)
    signed = _signed(desk, receipt)
    assert signed["cava"]["evidence_refs"] == ["q:000001", INTENT_REF, ZK_REF]
    assert "funds" not in receipt
    assert signed["funds"] == {
        "kind": "zktls",
        "evidence_ref": ZK_REF,
        "presentation_sha256": ZK_SHA,
        "server_name": "sandbox.increase.com",
        "session_time": NOW - 5,
        "notary_key": NOTARY,
    }


@pytest.mark.parametrize(
    ("disclosed", "reason"),
    [
        (increase_disclosed(balance=19999), "zktls: insufficient funds"),
        (increase_disclosed(nonce="0" * 64), "zktls: not bound to this intent"),
        (increase_disclosed(time=NOW - 301), "zktls: stale session"),
    ],
)
def test_refused_proofs_keep_the_cooperative_path(
    zk_desk, sign_quote, disclosed, reason
):
    desk, holder = zk_desk(disclosed)
    assert desk.record_funds_proof("i:000001", PROOF) == {
        "status": "denied",
        "intent_id": "i:000001",
        "reason": reason,
    }
    signed = _signed(desk, _pay(desk, holder, sign_quote))
    coop = signed["cava"]["evidence_refs"][2]
    assert coop.startswith("ev:cooperative-signed:")
    assert signed["funds"] == {
        "kind": "cooperative",
        "evidence_ref": coop,
        "presentation_sha256": None,
        "server_name": None,
        "session_time": None,
        "notary_key": None,
    }


def test_a_paid_intent_takes_no_proof(zk_desk, sign_quote):
    desk, holder = zk_desk()
    _pay(desk, holder, sign_quote)
    assert desk.record_funds_proof("i:000001", PROOF) == {
        "status": "denied",
        "intent_id": "i:000001",
        "reason": "intent: already used",
    }


def test_an_unsettled_intent_takes_no_proof(zk_desk, sign_quote):
    desk, holder = zk_desk()
    desk.bank.error = RailError("bank: outcome unknown")
    _pay(desk, holder, sign_quote)
    assert desk.record_funds_proof("i:000001", PROOF) == {
        "status": "denied",
        "intent_id": "i:000001",
        "reason": "intent: unsettled",
    }
    assert desk.intent_receipt("i:000001")["evidence_ref"].startswith(
        "ev:cooperative-signed:"
    )


def test_a_desk_without_zktls_refuses_every_proof(make_desk):
    lines = []
    desk, _ = make_desk(
        bank=RecordingRail(balance=50000), intents=(DEMO_INTENT,), publish=lines.append
    )
    for intent_id in ("i:000001", "i:000009"):
        assert desk.record_funds_proof(intent_id, PROOF) == {
            "status": "denied",
            "intent_id": intent_id,
            "reason": "zktls: not configured",
        }
    assert [(x.subject["status"], x.subject["reason"]) for x in lines[-2:]] == [
        ("denied", "zktls: not configured"),
    ] * 2


def test_unknown_intents_publish_nothing(zk_desk):
    lines = []
    desk, _ = zk_desk(publish=lines.append)
    before = len(lines)
    assert desk.record_funds_proof("i:000009", PROOF) == {
        "status": "unknown",
        "intent_id": "i:000009",
    }
    assert len(lines) == before


def test_proof_lines_never_carry_the_balance_or_the_account(zk_desk):
    lines = []
    desk, _ = zk_desk(increase_disclosed(balance=73123), publish=lines.append)
    desk.record_funds_proof("i:000001", PROOF)
    proven = lines[-1]
    assert (proven.subject["step"], proven.subject["status"]) == ("intent", "proven")
    seen = [console_line_json(line) for line in lines]
    seen.append(json.dumps(desk.intent_receipt("i:000001")))
    assert all("73123" not in text and ACCT not in text for text in seen)


def test_zktls_needs_the_sandbox_rail(make_desk, tmp_path):
    setup = BankProofSetup(
        fake_verifier(tmp_path, increase_disclosed()), "a", NOTARY, {}
    )
    with pytest.raises(ValueError, match="^zktls needs the sandbox rail$"):
        make_desk(zktls=setup)


def test_an_unbound_simulated_payment_has_no_funds_view(make_desk, sign_quote):
    desk, holder = make_desk()
    receipt = _pay(desk, holder, sign_quote, intent_id=None)
    assert _signed(desk, receipt)["funds"] is None


def test_desk_zktls_receipt_is_the_golden(zk_desk, sign_quote):
    desk, holder = zk_desk(gate_key=GATE, holder_key=HOLDER)
    desk.record_funds_proof("i:000001", PROOF)
    text = json.dumps(_pay(desk, holder, sign_quote), separators=(",", ":")) + "\n"
    if os.environ.get("MANDATE_GOLDEN") == "1":
        GOLDEN_ZKTLS.write_text(text)
    assert text == GOLDEN_ZKTLS.read_text()


def test_desk_cooperative_receipt_is_the_golden(zk_desk, sign_quote):
    desk, holder = zk_desk(gate_key=GATE, holder_key=HOLDER, bank_key=bytes([7]) * 32)
    receipt = _pay(desk, holder, sign_quote)
    assert _signed(desk, receipt)["funds"]["evidence_ref"] == COOP_REF
    text = json.dumps(receipt, separators=(",", ":")) + "\n"
    if os.environ.get("MANDATE_GOLDEN") == "1":
        GOLDEN_COOP.write_text(text)
    assert text == GOLDEN_COOP.read_text()
