import dataclasses
import os
from pathlib import Path

import pytest

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.policy import Intent
from gate.registry import Registry, verify_inclusion
from swarm.anchor import ReasoningAnchor, verify_anchor
from swarm.flow import PAYMENTS_POLICY, run_bill
from swarm.meta_client import MetaClient, api_key_from_env

BILL = Path(__file__).resolve().parent.parent / "demo" / "bills" / "acme-A-991.pdf"


@pytest.mark.live
def test_live_anchor_binds_certificate():
    try:
        key = api_key_from_env(dict(os.environ))
    except KeyError:
        pytest.skip("live: set MODEL_API_KEY or META_API_KEY")
    priv, pub = generate_keypair()
    run = run_bill(
        MetaClient(key),
        BILL.read_bytes(),
        BILL.name,
        "Pay this bill for me.",
        Intent(20000, "USD", "acme-991", "A-991"),
        PAYMENTS_POLICY,
        priv,
        Bank({"checking-881": 50000, "acme-991": 0}),
        Verifier(pub),
        1800001000,
        "d1" * 16,
        0,
        source="checking-881",
    )
    anchor = run.proposal.anchor
    assert run.result.certificate is not None
    assert verify_anchor(anchor, run.result.certificate, pub) == (
        True,
        "ok: anchor bound",
    )
    registry = Registry()
    assert registry.append("anchor", anchor.to_json()) == 1
    assert verify_inclusion(registry.prove(1), registry.root()) is True
    assert ReasoningAnchor.from_json(anchor.to_json()) == anchor
    forged = dataclasses.replace(anchor, response_id="resp_forged")
    assert verify_anchor(forged, run.result.certificate, pub) == (
        False,
        "mismatch: reasoning differs",
    )
