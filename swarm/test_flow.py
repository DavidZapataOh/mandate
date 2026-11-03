import json

import pytest

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.policy import Intent, Verdict
from swarm.agent import ProposalError
from swarm.conftest import ARGS, REASONING, message, tool_call
from swarm.flow import PAYMENTS_POLICY, run_bill
from swarm.meta_client import MetaAPIError

NOW = 1800001000
NONCE = "ab" * 16
INTENT = Intent(
    amount_cents=20000, currency="USD", recipient="acme-991", reference="A-991"
)


def _bank():
    return Bank({"checking-881": 50000, "acme-991": 0, "evil-666": 0})


def _run(meta, bank):
    priv, pub = generate_keypair()
    return run_bill(
        meta,
        b"%PDF",
        "acme.pdf",
        "Pay this bill.",
        INTENT,
        PAYMENTS_POLICY,
        priv,
        bank,
        Verifier(pub),
        NOW,
        NONCE,
        0,
        source="checking-881",
    )


def test_run_bill_executes_matching_payment(fake_meta):
    meta = fake_meta([REASONING, tool_call()], [message("Paid.")])
    bank = _bank()
    run = _run(meta, bank)
    assert run.result.verdict is Verdict.MET
    assert run.result.reason == "ok: executed"
    assert bank.get_balance("acme-991") == 20000
    assert bank.get_balance("checking-881") == 30000
    sent = json.loads(meta.requests[1]["input"][-1]["output"])
    assert sent == {
        "payment": "pay:000001",
        "reason": "ok: executed",
        "status": "executed",
    }
    assert run.confirmation == "Paid."
    assert run.report_error is None


def test_run_bill_denies_hijacked_payee(fake_meta):
    hijacked = tool_call(dict(ARGS, to_account="evil-666"))
    meta = fake_meta([REASONING, hijacked], [message("Denied.")])
    bank = _bank()
    run = _run(meta, bank)
    assert run.result.verdict is Verdict.NOT_MET
    assert run.result.reason == "recipient differs from intent"
    assert run.result.payment is None
    assert bank.get_balance("evil-666") == 0
    assert bank.get_balance("checking-881") == 50000
    sent = json.loads(meta.requests[1]["input"][-1]["output"])
    assert sent["status"] == "denied"


def test_run_bill_stops_before_gate_on_bad_proposal(fake_meta):
    meta = fake_meta([REASONING, message("This bill looks wrong.")])
    bank = _bank()
    with pytest.raises(ProposalError, match="no payment proposed"):
        _run(meta, bank)
    assert bank.get_balance("checking-881") == 50000
    assert len(meta.requests) == 1


def test_run_bill_debits_only_the_human_source(fake_meta):
    meta = fake_meta([REASONING, tool_call()], [message("Paid.")])
    bank = Bank({"checking-881": 50000, "savings-002": 50000, "acme-991": 0})
    _run(meta, bank)
    assert bank.get_balance("savings-002") == 50000
    assert bank.get_balance("checking-881") == 30000


def test_run_bill_keeps_result_when_confirmation_fails(fake_meta):
    meta = fake_meta([REASONING, tool_call()], MetaAPIError("HTTP 503: unavailable"))
    bank = _bank()
    run = _run(meta, bank)
    assert run.result.reason == "ok: executed"
    assert run.result.payment is not None
    assert run.result.payment.payment_id == "pay:000001"
    assert run.confirmation is None
    assert run.report_error == "HTTP 503: unavailable"
    assert bank.get_balance("acme-991") == 20000
