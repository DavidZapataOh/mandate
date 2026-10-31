import subprocess
import sys
from pathlib import Path

import pytest

from bank.api import Bank, PaymentRequest
from bank.verifier import Freshness, ProposedAction, Verifier, action_hash
from gate.cava import CavaAction
from gate.cava import Freshness as GateFreshness
from gate.cava import action_hash as gate_action_hash
from gate.certs import (
    CertClaims,
    SingleUseStore,
    generate_keypair,
    issue_certificate,
)
from gate.policy import Verdict


def _bank():
    return Bank({"checking-881": 50000, "acme-991": 0})


def _request(**over):
    fields = {
        "from_acct": "checking-881",
        "to_acct": "acme-991",
        "amount_cents": 20000,
        "currency": "USD",
        "ref": "A-991",
    }
    fields.update(over)
    return PaymentRequest(**fields)


def test_bank_flows():
    bank = _bank()
    first = bank.execute(_request(), "h1")
    assert (first.payment_id, first.action_hash) == ("pay:000001", "h1")
    assert bank.get_balance("checking-881") == 30000
    assert bank.get_balance("acme-991") == 20000
    assert bank.get_payment("pay:000001") == first
    second = bank.execute(_request(ref="A-992"), "h2")
    assert second.payment_id == "pay:000002"
    assert bank.accounts() == ("acme-991", "checking-881")


def test_bank_rejects_bad_ops():
    bank = _bank()
    with pytest.raises(ValueError, match="unknown account: nope"):
        bank.execute(_request(from_acct="nope"), "h")
    with pytest.raises(ValueError, match="insufficient funds: checking-881"):
        bank.execute(_request(amount_cents=60000), "h")
    with pytest.raises(ValueError, match="unknown account: nope"):
        bank.get_balance("nope")
    with pytest.raises(ValueError, match="unknown payment: pay:000009"):
        bank.get_payment("pay:000009")
    assert bank.get_balance("checking-881") == 50000
    assert bank.accounts() == ("acme-991", "checking-881")
    with pytest.raises(ValueError, match="initial balance must be"):
        Bank({"checking-881": -1})
    with pytest.raises(ValueError, match="amount must be positive"):
        _request(amount_cents=0)
    with pytest.raises(ValueError, match="payment fields must be non-empty"):
        _request(ref="")


NONCE = "aa11bb22cc33dd44ee55ff6600112233"
TS = 1800000000
NOW = 1800000100
TARGETS = (
    "acct:checking-881",
    "amount:USD:20000",
    "from:checking-881",
    "merchant:acme-991",
    "ref:A-991",
    "to:acme-991",
)


def _proposed(targets=TARGETS):
    return ProposedAction(
        version="cava/1",
        runtime="mcp",
        executable="bank.pay",
        operation="transfer",
        category="payments",
        targets=targets,
        reversible=False,
        freshness=Freshness(nonce=NONCE, timestamp=TS),
        evidence_refs=("ev:funds-proof-7f3a",),
    )


def _gate_action(targets=TARGETS):
    return CavaAction(
        version="cava/1",
        runtime="mcp",
        executable="bank.pay",
        operation="transfer",
        category="payments",
        targets=targets,
        reversible=False,
        freshness=GateFreshness(nonce=NONCE, timestamp=TS),
        evidence_refs=("ev:funds-proof-7f3a",),
    )


def _claims(digest, index=7):
    return CertClaims(
        action_hash=digest,
        policy_id="payments",
        policy_version=1,
        verdict=Verdict.MET,
        freshness_nonce=NONCE,
        issued_at=TS,
        expires_at=TS + 300,
        scope="mcp:bank.pay:transfer:checking-881",
        reasoning_commitment="b5" * 32,
        evidence_refs=("ev:funds-proof-7f3a",),
        revocation_index=index,
    )


def _token(digest, private_key, jti, index=7):
    return issue_certificate(_claims(digest, index), private_key, jti)


def test_hash_matches_gate():
    assert action_hash(_proposed()) == gate_action_hash(_gate_action())


def test_mismatch_denied(keypair):
    priv, pub = keypair
    token = _token(gate_action_hash(_gate_action()), priv, "bank-jti-1")
    mutated = ("amount:USD:200000", "to:evil-999")
    for bad_target in mutated:
        bank = Bank({"checking-881": 50000, "acme-991": 0})
        prefix = bad_target.split(":")[0] + ":"
        targets = tuple(bad_target if t.startswith(prefix) else t for t in TARGETS)
        result = Verifier(pub).verify_and_execute(bank, token, _proposed(targets), NOW)
        assert (result.accepted, result.reason, result.payment) == (
            False,
            "mismatch: action hash differs",
            None,
        )
        assert bank.get_balance("checking-881") == 50000


def test_unverifiable_token_denied(keypair):
    priv, pub = keypair
    digest = gate_action_hash(_gate_action())
    verifier = Verifier(pub)
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = verifier.verify_and_execute(bank, "garbage.token.here", _proposed(), NOW)
    assert (result.accepted, result.reason) == (
        False,
        "malformed: token undecodable",
    )
    _, wrong_pub = generate_keypair()
    token = _token(digest, priv, "bank-jti-2")
    result = Verifier(wrong_pub).verify_and_execute(bank, token, _proposed(), NOW)
    assert (result.accepted, result.reason) == (
        False,
        "bad-signature: eddsa mismatch",
    )
    result = verifier.verify_and_execute(bank, token, _proposed(), TS + 301)
    assert (result.accepted, result.reason) == (False, "stale: token expired")
    assert bank.get_balance("checking-881") == 50000


def test_not_a_payment_denied(keypair):
    priv, pub = keypair
    targets = ("file:/etc/passwd",)
    token = _token(gate_action_hash(_gate_action(targets)), priv, "bank-jti-3")
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = Verifier(pub).verify_and_execute(bank, token, _proposed(targets), NOW)
    assert (result.accepted, result.reason) == (
        False,
        "denied: action is not a payment",
    )


def test_double_spend_denied(keypair):
    priv, pub = keypair
    token = _token(gate_action_hash(_gate_action()), priv, "bank-jti-4")
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    verifier = Verifier(pub)
    first = verifier.verify_and_execute(bank, token, _proposed(), NOW)
    assert (first.accepted, first.reason) == (True, "ok: executed")
    assert first.payment is not None and first.payment.payment_id == "pay:000001"
    second = verifier.verify_and_execute(bank, token, _proposed(), NOW)
    assert (second.accepted, second.reason, second.payment) == (
        False,
        "replay: jti consumed",
        None,
    )
    assert bank.get_balance("checking-881") == 30000
    assert bank.get_balance("acme-991") == 20000


def test_revoked_denied(keypair):
    priv, pub = keypair
    token = _token(gate_action_hash(_gate_action()), priv, "bank-jti-5")
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    verifier = Verifier(pub)
    verifier.revoke(7)
    result = verifier.verify_and_execute(bank, token, _proposed(), NOW)
    assert (result.accepted, result.reason) == (False, "revoked: bit set")
    assert bank.get_balance("checking-881") == 50000
    with pytest.raises(IndexError, match="revocation index out of range"):
        verifier.revoke(1024)


def test_revocation_index_guarded(keypair):
    priv, pub = keypair
    token = _token(gate_action_hash(_gate_action()), priv, "bank-jti-7", index=5000)
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = Verifier(pub).verify_and_execute(bank, token, _proposed(), NOW)
    assert (result.accepted, result.reason) == (
        False,
        "malformed: revocation index out of range",
    )
    assert bank.get_balance("checking-881") == 50000


def test_bank_store_independent(keypair):
    priv, pub = keypair
    token = _token(gate_action_hash(_gate_action()), priv, "bank-jti-6")
    gate_store = SingleUseStore()
    assert gate_store.consume("bank-jti-6") is True
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = Verifier(pub).verify_and_execute(bank, token, _proposed(), NOW)
    assert (result.accepted, result.reason) == (True, "ok: executed")


ROOT = Path(__file__).resolve().parent.parent


def test_verifier_isolated():
    code = (
        "import sys; import bank.api, bank.verifier; "
        "bad = [m for m in sys.modules "
        "if m == 'gate' or m.startswith('gate.')]; "
        "assert not bad, bad"
    )
    run = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert run.returncode == 0, run.stderr
