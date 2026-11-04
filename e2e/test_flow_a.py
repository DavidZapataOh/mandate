import json
from pathlib import Path

from bank.api import Bank
from bank.verifier import Verifier
from evidence.cooperative import sign_state, verify_state
from evidence.seams import select_best
from gate.certs import generate_keypair
from gate.policy import Intent, Policy, Rule, Verdict
from gate.registry import Registry, verify_inclusion
from gate.shim import Mode, RawCall
from mandate.cli import main
from mandate.client import RunRequest, RunResult, run_governed

FLOW_NONCE = "ee11ff22aa3300445566778899001133"
FLOW_TS = 1800001000
FLOW_NOW = 1800001100
ANCHOR_TS = 1800001200
EREF = "ev:cooperative-signed:d91ab6d7bda00f57a1598f374dac37b7"
FLOW_SALT = b"\x0f" * 32
FLOW_ACTION = "f76301d0aad22b0a25a17f5f68d5e64c6198b8006f09333b5a8a7bfa053484e3"


def _flow_call(eref: str) -> RawCall:
    return RawCall(
        runtime="cli",
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
        evidence_refs=(eref,),
        reversible=False,
    )


def _flow_policy() -> Policy:
    return Policy(
        policy_id="payments",
        version=1,
        rules=(
            Rule(
                rule_id="pay-exact",
                actor="cli:bank.pay",
                operation="transfer",
                target="to:acme-991",
                amount_exact=True,
                amount_lte_cents=None,
                approval_required=False,
            ),
        ),
    )


def _flow_intent() -> Intent:
    return Intent(
        amount_cents=20000,
        currency="USD",
        recipient="acme-991",
        reference="A-991",
    )


def _governed(gate_priv: bytes, bank: Bank, verifier: Verifier) -> RunResult:
    return run_governed(
        RunRequest(
            call=_flow_call(EREF),
            policy=_flow_policy(),
            intent=_flow_intent(),
            private_key=gate_priv,
            mode=Mode.ENFORCE,
            now=FLOW_NOW,
            nonce=FLOW_NONCE,
            timestamp=FLOW_TS,
            scope="flow-a",
            reasoning_commitment="aa" * 32,
            revocation_index=0,
            salt=FLOW_SALT,
        ),
        bank,
        verifier,
    )


def _policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "policy_id": "payments",
                "version": 1,
                "rules": [
                    {
                        "rule_id": "pay-exact",
                        "actor": "cli:bank.pay",
                        "operation": "transfer",
                        "target": "to:acme-991",
                        "amount_exact": True,
                        "amount_lte_cents": None,
                        "approval_required": False,
                    }
                ],
            }
        )
    )
    return path


def test_flow_a_receipt_anchored(tmp_path, capsys):
    bank_priv, bank_pub = generate_keypair()
    coop = sign_state(
        bank_priv,
        "checking-881",
        "funds-sufficient",
        50000,
        "USD",
        FLOW_NONCE,
        FLOW_TS,
    )
    ok, _reason = verify_state(coop, bank_pub, FLOW_NOW)
    assert ok is True
    assert select_best(coop, None) == EREF
    cli_nonce = "ff11aa22bb3300445566778899001144"
    argv = [
        "run",
        "--policy",
        str(_policy_file(tmp_path)),
        "--amount-cents",
        "20000",
        "--currency",
        "USD",
        "--to",
        "acme-991",
        "--from",
        "checking-881",
        "--ref",
        "A-991",
        "--evidence-ref",
        EREF,
        "--now",
        str(FLOW_NOW),
        "--nonce",
        cli_nonce,
    ]
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert out == f"EXECUTED payment=pay:000001 event=evt:{cli_nonce}\n"
    gate_priv, gate_pub = generate_keypair()
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    verifier = Verifier(gate_pub)
    result = _governed(gate_priv, bank, verifier)
    assert result.verdict is Verdict.MET
    assert result.reason == "ok: executed"
    assert result.event.action_hash == FLOW_ACTION
    assert result.payment is not None
    assert result.payment.payment_id == "pay:000001"
    assert result.payment.action_hash == result.event.action_hash
    assert bank.get_balance("checking-881") == 30000
    body = json.dumps(
        {
            "action": result.event.action_hash,
            "event_id": result.event.event_id,
            "payment_id": result.payment.payment_id,
            "reason": result.reason,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    reg_priv, reg_pub = generate_keypair()
    registry = Registry(keypair=(reg_priv, reg_pub))
    assert registry.append("execution", body) == 1
    anchor = registry.anchor(ANCHOR_TS)
    assert (anchor.seq_from, anchor.seq_to) == (1, 1)
    proof = registry.prove(1)
    assert proof.root == anchor.root
    assert verify_inclusion(proof, anchor.root) is True
    foreign = Registry()
    foreign.append("denial", body)
    assert verify_inclusion(proof, foreign.root()) is False
    rerun = _governed(gate_priv, bank, verifier)
    assert (rerun.payment, rerun.reason) == (None, "replay: jti consumed")
    assert bank.get_balance("checking-881") == 30000
