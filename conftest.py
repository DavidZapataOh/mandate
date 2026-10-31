"""Shared pytest fixtures (lives outside packages, never shipped)."""

import pytest

from gate.cava import CavaAction, Freshness
from gate.certs import CertClaims, generate_keypair
from gate.policy import Intent, Policy, Rule, Verdict


@pytest.fixture
def sample_action() -> CavaAction:
    return CavaAction(
        version="cava/1",
        runtime="mcp",
        executable="bank.pay",
        operation="transfer",
        category="payments",
        targets=(
            "acct:checking-881",
            "merchant:acme-991",
            "amount:USD:20000",
            "to:acme-991",
            "from:checking-881",
            "ref:A-991",
        ),
        reversible=False,
        freshness=Freshness(
            nonce="deadbeef00112233445566778899aabbcc", timestamp=1800000000
        ),
        evidence_refs=("ev:funds-proof-7f3a",),
    )


@pytest.fixture
def sample_intent() -> Intent:
    return Intent(
        amount_cents=20000,
        currency="USD",
        recipient="acme-991",
        reference="A-991",
    )


@pytest.fixture
def sample_policy() -> Policy:
    return Policy(
        policy_id="payments",
        version=1,
        rules=(
            Rule(
                rule_id="pay-exact",
                actor="mcp:bank.pay",
                operation="transfer",
                target="to:acme-991",
                amount_exact=True,
                amount_lte_cents=None,
                approval_required=False,
            ),
        ),
    )


@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def cert_claims() -> CertClaims:
    return CertClaims(
        action_hash="5393e9fa493501ae0f5a7247bd5e8c6722b37d05996e2baab609ac920990002b",
        policy_id="payments",
        policy_version=1,
        verdict=Verdict.MET,
        freshness_nonce="deadbeef00112233445566778899aabbcc",
        issued_at=1800000000,
        expires_at=1800000300,
        scope="mcp:bank.pay:transfer:checking-881",
        reasoning_commitment="b5" * 32,
        evidence_refs=("ev:funds-proof-7f3a",),
        revocation_index=7,
    )
