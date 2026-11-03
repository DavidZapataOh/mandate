import json
import os

import pytest

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.policy import Intent
from gate.shim import RawCall
from swarm.attacker import attacker_from_env
from swarm.redteam import AttackKind, apply_attack

LEGIT = RawCall(
    runtime="muse",
    executable="bank.pay",
    operation="transfer",
    args=(
        ("amount", "20000"),
        ("currency", "USD"),
        ("from", "checking-881"),
        ("to", "acme-991"),
        ("ref", "A-991"),
    ),
    category="payments",
    evidence_refs=(),
    reversible=False,
)


@pytest.mark.live
def test_live_campaign_all_blocked(tmp_path):
    if not os.environ.get("BASETEN_API_KEY"):
        pytest.skip("live: set BASETEN_API_KEY")
    attacker = attacker_from_env(dict(os.environ))
    assert attacker.provider == "baseten"
    priv, pub = generate_keypair()
    bank = Bank({"checking-881": 200000, "acme-991": 0})
    intent = Intent(20000, "USD", "acme-991", "A-991")
    log = tmp_path / "campaign.jsonl"
    applied = 0
    with log.open("w") as out:
        for i, kind in enumerate(AttackKind):
            plan, trace, text = attacker.next_plan(kind, LEGIT)
            assert trace.provider == "baseten"
            assert "muse-spark-open" in trace.model
            row = {
                "kind": kind,
                "plan_kind": plan.kind if plan else None,
                "blocked": None,
                "provider": trace.provider,
                "model": trace.model,
                "request_id": trace.request_id,
                "raw": text[:200],
            }
            if plan is not None:
                outcome = apply_attack(
                    plan,
                    LEGIT,
                    intent,
                    priv,
                    bank,
                    Verifier(pub),
                    "checking-881",
                    1800000000 + i,
                    f"live{i:028d}",
                )
                assert plan.kind == kind, (plan.kind, kind)
                assert outcome.blocked is True, outcome
                row["blocked"] = outcome.blocked
                row["reason"] = outcome.reason
                applied += 1
            out.write(json.dumps(row) + "\n")
    assert applied >= 4
    print(log.read_text())
    print(f"{applied}/6 attack kinds exercised, all {applied} blocked")
