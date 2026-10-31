"""Perf gate: real decide-path measurements against locked budgets."""

import itertools
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from bench.runner import check_budgets, run_bench
from gate.approval import freeze_proposal, verify_approval
from gate.cava import action_hash
from gate.certs import (
    BitstringRevocation,
    SingleUseStore,
    issue_certificate,
    verify_certificate,
)
from gate.policy import evaluate
from gate.shim import Mode, RawCall, decide

BUDGETS = Path(__file__).resolve().parent.parent / "bench" / "budgets.toml"

PERF_CALL = RawCall(
    runtime="mcp",
    executable="bank.pay",
    operation="transfer",
    args=(("to", "acme-991"), ("amount", "20000"), ("currency", "USD")),
    category="payments",
    evidence_refs=(),
    reversible=False,
)


def test_perf_within_budgets(
    sample_action, sample_policy, sample_intent, keypair, cert_claims
):
    action = sample_action
    policy = sample_policy
    intent = sample_intent
    private_key, public_key = keypair
    token = issue_certificate(cert_claims, private_key, "perf-jti")
    payload = freeze_proposal(action, "payments", 1800000000)
    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    sig = priv.sign(payload.signable_bytes())
    counter = itertools.count()

    def _cava():
        action_hash(action)
        return {"ops": 1}

    def _policy():
        evaluate(action, policy, intent)
        return {"ops": 1}

    def _certs():
        verify_certificate(
            token, public_key, 1800000100, SingleUseStore(), BitstringRevocation()
        )
        return {"ops": 1}

    def _shim():
        decide(
            PERF_CALL,
            policy,
            intent,
            private_key,
            mode=Mode.ENFORCE,
            now=1800000100,
            nonce=f"perf-{next(counter):06d}",
            timestamp=1800000000,
            scope="perf",
            reasoning_commitment="p" * 64,
            revocation_index=1,
        )
        return {"ops": 1}

    def _approval():
        verify_approval(public_key, payload, sig, action, 1800000100)
        return {"ops": 1}

    results = [
        run_bench("gate.cava.hash", _cava, n=2000, warmup=200),
        run_bench("gate.policy.evaluate", _policy, n=2000, warmup=200),
        run_bench("gate.certs.verify", _certs, n=2000, warmup=200),
        run_bench("gate.shim.decide", _shim, n=2000, warmup=200),
        run_bench("gate.approval.verify", _approval, n=2000, warmup=200),
    ]
    breaches = check_budgets(results, BUDGETS)
    assert breaches == []
