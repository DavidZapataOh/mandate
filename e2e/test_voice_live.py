import os
from pathlib import Path

import pytest

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.policy import Intent, Verdict
from swarm.flow import PAYMENTS_POLICY, run_bill
from swarm.intent import PayeeBook, confirmed_intent, draft_intent, sign_intent
from swarm.meta_client import MetaClient, api_key_from_env
from swarm.voice import transcribe

DEMO = Path(__file__).resolve().parent.parent / "demo"
BOOK = PayeeBook.from_json(
    {"acme corp": {"account": "acme-991", "open_invoices": ["A-991"]}}
)


@pytest.mark.live
def test_live_voice_to_payment():
    try:
        key = api_key_from_env(dict(os.environ))
    except KeyError:
        pytest.skip("live: set MODEL_API_KEY or META_API_KEY")
    clip = (DEMO / "voice" / "pay-acme.wav").read_bytes()
    spoken = transcribe(key, clip, ("Acme", "A-991"))
    assert "acme" in spoken.text.lower()
    meta = MetaClient(key)
    draft, _ = draft_intent(meta, spoken.text, BOOK)
    assert draft == Intent(20000, "USD", "acme-991", "A-991")
    holder_priv, holder_pub = generate_keypair()
    intent = confirmed_intent(holder_pub, draft, sign_intent(holder_priv, draft))
    gate_priv, gate_pub = generate_keypair()
    bill = DEMO / "bills" / "acme-A-991.pdf"
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    run = run_bill(
        meta,
        bill.read_bytes(),
        bill.name,
        "Pay this bill for me.",
        intent,
        PAYMENTS_POLICY,
        gate_priv,
        bank,
        Verifier(gate_pub),
        1800001000,
        "f1" * 16,
        0,
        source="checking-881",
    )
    assert run.result.verdict is Verdict.MET
    assert bank.get_balance("acme-991") == 20000
