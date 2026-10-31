"""Shared pytest fixtures (lives outside packages, never shipped)."""

import pytest

from gate.cava import CavaAction, Freshness
from gate.policy import Intent, Policy, Rule


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
