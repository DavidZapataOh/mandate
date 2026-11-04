import subprocess
import sys
from pathlib import Path

import pytest

from bank.api import Bank, PaymentRequest
from bank.verifier import (
    Freshness,
    ProposedAction,
    Verifier,
    action_commitment,
)
from gate.cava import CavaAction
from gate.cava import Freshness as GateFreshness
from gate.cava import action_commitment as gate_commitment
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
SALT = b"\x5a" * 32
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
        scope="mcp:bank.pay:transfer",
        reasoning_commitment="b5" * 32,
        evidence_refs=("ev:funds-proof-7f3a",),
        revocation_index=index,
    )


def _token(digest, private_key, jti, index=7):
    return issue_certificate(_claims(digest, index), private_key, jti)


def test_mismatch_denied(keypair):
    priv, pub = keypair
    token = _token(gate_commitment(_gate_action(), SALT), priv, "bank-jti-1")
    mutated = ("amount:USD:200000", "to:evil-999")
    for bad_target in mutated:
        bank = Bank({"checking-881": 50000, "acme-991": 0})
        prefix = bad_target.split(":")[0] + ":"
        targets = tuple(bad_target if t.startswith(prefix) else t for t in TARGETS)
        result = Verifier(pub).verify_and_execute(
            bank, token, _proposed(targets), NOW, SALT
        )
        assert (result.accepted, result.reason, result.payment) == (
            False,
            "mismatch: action hash differs",
            None,
        )
        assert bank.get_balance("checking-881") == 50000


def test_unverifiable_token_denied(keypair):
    priv, pub = keypair
    digest = gate_commitment(_gate_action(), SALT)
    verifier = Verifier(pub)
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = verifier.verify_and_execute(
        bank, "garbage.token.here", _proposed(), NOW, SALT
    )
    assert (result.accepted, result.reason) == (
        False,
        "malformed: token undecodable",
    )
    _, wrong_pub = generate_keypair()
    token = _token(digest, priv, "bank-jti-2")
    result = Verifier(wrong_pub).verify_and_execute(bank, token, _proposed(), NOW, SALT)
    assert (result.accepted, result.reason) == (
        False,
        "bad-signature: eddsa mismatch",
    )
    result = verifier.verify_and_execute(bank, token, _proposed(), TS + 301, SALT)
    assert (result.accepted, result.reason) == (False, "stale: token expired")
    assert bank.get_balance("checking-881") == 50000


def test_not_a_payment_denied(keypair):
    priv, pub = keypair
    targets = ("file:/etc/passwd",)
    token = _token(gate_commitment(_gate_action(targets), SALT), priv, "bank-jti-3")
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = Verifier(pub).verify_and_execute(
        bank, token, _proposed(targets), NOW, SALT
    )
    assert (result.accepted, result.reason) == (
        False,
        "denied: action is not a payment",
    )


def test_double_spend_denied(keypair):
    priv, pub = keypair
    token = _token(gate_commitment(_gate_action(), SALT), priv, "bank-jti-4")
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    verifier = Verifier(pub)
    first = verifier.verify_and_execute(bank, token, _proposed(), NOW, SALT)
    assert (first.accepted, first.reason) == (True, "ok: executed")
    assert first.payment is not None and first.payment.payment_id == "pay:000001"
    second = verifier.verify_and_execute(bank, token, _proposed(), NOW, SALT)
    assert (second.accepted, second.reason, second.payment) == (
        False,
        "replay: jti consumed",
        None,
    )
    assert bank.get_balance("checking-881") == 30000
    assert bank.get_balance("acme-991") == 20000


def test_revoked_denied(keypair):
    priv, pub = keypair
    token = _token(gate_commitment(_gate_action(), SALT), priv, "bank-jti-5")
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    verifier = Verifier(pub)
    verifier.revoke(7)
    result = verifier.verify_and_execute(bank, token, _proposed(), NOW, SALT)
    assert (result.accepted, result.reason) == (False, "revoked: bit set")
    assert bank.get_balance("checking-881") == 50000
    with pytest.raises(IndexError, match="revocation index out of range"):
        verifier.revoke(1024)


def test_revocation_index_guarded(keypair):
    priv, pub = keypair
    token = _token(
        gate_commitment(_gate_action(), SALT), priv, "bank-jti-7", index=5000
    )
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = Verifier(pub).verify_and_execute(bank, token, _proposed(), NOW, SALT)
    assert (result.accepted, result.reason) == (
        False,
        "malformed: revocation index out of range",
    )
    assert bank.get_balance("checking-881") == 50000


def test_bank_store_independent(keypair):
    priv, pub = keypair
    token = _token(gate_commitment(_gate_action(), SALT), priv, "bank-jti-6")
    gate_store = SingleUseStore()
    assert gate_store.consume("bank-jti-6") is True
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = Verifier(pub).verify_and_execute(bank, token, _proposed(), NOW, SALT)
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


@pytest.mark.parametrize(
    "targets",
    [
        (
            "amount:USD:0",
            "amount:USD:200000",
            "from:checking-881",
            "ref:A-991",
            "to:acme-991",
        ),
        (
            "amount:USD:20000",
            "from:checking-881",
            "ref:A-991",
            "to:acme-991",
            "to:evil-666",
        ),
        (
            "amount:USD:20000",
            "from:checking-881",
            "from:savings-1",
            "ref:A-991",
            "to:acme-991",
        ),
        (
            "amount:USD:20000",
            "from:checking-881",
            "ref:A-991",
            "ref:B-1",
            "to:acme-991",
        ),
    ],
)
def test_duplicate_payment_fields_denied(keypair, targets):
    priv, pub = keypair
    token = _token(gate_commitment(_gate_action(targets), SALT), priv, "bank-jti-dup")
    bank = Bank({"checking-881": 500000, "acme-991": 0, "evil-666": 0})
    result = Verifier(pub).verify_and_execute(
        bank, token, _proposed(targets), NOW, SALT
    )
    assert (result.accepted, result.reason, result.payment) == (
        False,
        "denied: ambiguous payment fields",
        None,
    )
    assert bank.get_balance("checking-881") == 500000


def test_commitment_matches_gate():
    assert action_commitment(_proposed(), SALT) == gate_commitment(_gate_action(), SALT)


PROPOSED_COMMITMENT = "b64d8275a44f43242756acf83a77ce36f56a0b649056d0e3e988d82277c34105"
PROPOSED_SHA256 = "51b92f2c6746cc9f9441ea477f69f6232343cf74061016a8dde30619203846e5"


def test_commitment_is_hmac_sha256_keyed_by_the_salt():
    assert action_commitment(_proposed(), SALT) == PROPOSED_COMMITMENT
    assert action_commitment(_proposed(), b"\x5b" * 32) != PROPOSED_COMMITMENT


def test_a_certificate_over_the_unsalted_hash_pays_nothing(keypair):
    priv, pub = keypair
    assert gate_action_hash(_gate_action()) == PROPOSED_SHA256
    token = _token(PROPOSED_SHA256, priv, "bank-jti-raw")
    bank = _bank()
    result = Verifier(pub).verify_and_execute(bank, token, _proposed(), NOW, SALT)
    assert (result.accepted, result.reason) == (False, "mismatch: action hash differs")
    assert bank.get_balance("checking-881") == 50000


def test_another_salt_pays_nothing_and_burns_the_certificate(keypair):
    priv, pub = keypair
    token = _token(PROPOSED_COMMITMENT, priv, "bank-jti-salt")
    bank, verifier = _bank(), Verifier(pub)
    other = verifier.verify_and_execute(bank, token, _proposed(), NOW, b"\x5b" * 32)
    again = verifier.verify_and_execute(bank, token, _proposed(), NOW, SALT)
    assert (other.reason, again.reason) == (
        "mismatch: action hash differs",
        "replay: jti consumed",
    )
    assert bank.get_balance("checking-881") == 50000


@pytest.mark.parametrize("salt", [b"", b"\x5a" * 31, b"\x5a" * 33, "5a" * 32])
def test_a_malformed_salt_pays_nothing(keypair, salt):
    priv, pub = keypair
    token = _token(PROPOSED_COMMITMENT, priv, "bank-jti-bad-salt")
    bank = _bank()
    result = Verifier(pub).verify_and_execute(bank, token, _proposed(), NOW, salt)
    assert (result.accepted, result.reason, result.payment) == (
        False,
        "malformed: action salt",
        None,
    )
    assert bank.get_balance("checking-881") == 50000
