import dataclasses
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from gate.approval import freeze_proposal, summary_for, verify_approval
from gate.cava import action_hash


def _sign(private_key: bytes, payload) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    return priv.sign(payload.signable_bytes())


def test_signs_exact_hash(sample_action, keypair):
    payload = freeze_proposal(sample_action, "payments", 1800000000)
    assert payload.action_hash == action_hash(sample_action)
    assert payload.action_hash == (
        "5393e9fa493501ae0f5a7247bd5e8c6722b37d05996e2baab609ac920990002b"
    )
    assert payload.expires_at == 1800000600
    assert summary_for(sample_action) == (
        "Pay 200.00 USD to acme-991 (ref A-991).",
        "Hash 5393e9fa493501ae - payments - irreversible.",
    )
    private_key, public_key = keypair
    ok, reason = verify_approval(
        public_key, payload, _sign(private_key, payload), sample_action, 1800000100
    )
    assert (ok, reason) == (True, "ok: approved")


def test_mutation_denies(sample_action, keypair):
    payload = freeze_proposal(sample_action, "payments", 1800000000)
    private_key, public_key = keypair
    sig = _sign(private_key, payload)
    mutated = dataclasses.replace(
        sample_action,
        targets=(
            "acct:checking-881",
            "merchant:acme-991",
            "amount:USD:20001",
            "to:acme-991",
            "from:checking-881",
            "ref:A-991",
        ),
    )
    ok, reason = verify_approval(public_key, payload, sig, mutated, 1800000100)
    assert (ok, reason) == (False, "mismatch: action hash differs")


def test_freeze_guards(sample_action, keypair):
    payload = freeze_proposal(sample_action, "payments", 1800000000)
    private_key, public_key = keypair
    sig = _sign(private_key, payload)
    ok, reason = verify_approval(public_key, payload, sig, sample_action, 1800000601)
    assert (ok, reason) == (False, "expired: freeze window passed")
    bad = bytes([sig[0] ^ 1]) + sig[1:]
    ok, reason = verify_approval(public_key, payload, bad, sample_action, 1800000100)
    assert (ok, reason) == (False, "bad-signature: human signature invalid")


def test_freeze_contract(sample_action):
    payload = freeze_proposal(sample_action, "payments", 1800000000)
    wire = json.loads(payload.to_json())
    assert list(wire) == ["v", "action_hash", "summary", "policy_id", "expires_at"]
    assert wire["v"] == 1
    assert wire["summary"] == [
        "Pay 200.00 USD to acme-991 (ref A-991).",
        "Hash 5393e9fa493501ae - payments - irreversible.",
    ]
    assert payload.signable_bytes().startswith(b"freeze/v1:")
