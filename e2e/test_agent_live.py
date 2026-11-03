import contextlib
import os
from pathlib import Path

import pytest

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.policy import Intent, Verdict
from swarm.agent import ProposalError
from swarm.flow import PAYMENTS_POLICY, run_bill
from swarm.meta_client import MetaAPIError, MetaClient, api_key_from_env

BILLS = Path(__file__).resolve().parent.parent / "demo" / "bills"
INTENT = Intent(
    amount_cents=20000, currency="USD", recipient="acme-991", reference="A-991"
)
NOW = 1800001000


def _key():
    try:
        return api_key_from_env(dict(os.environ))
    except KeyError:
        pytest.skip("live: set MODEL_API_KEY or META_API_KEY")


def _run(meta, name, bank, nonce):
    priv, pub = generate_keypair()
    pdf = (BILLS / name).read_bytes()
    return run_bill(
        meta,
        pdf,
        name,
        "Pay this bill for me.",
        INTENT,
        PAYMENTS_POLICY,
        priv,
        bank,
        Verifier(pub),
        NOW,
        nonce,
        0,
        source="checking-881",
    )


@pytest.mark.live
def test_live_clean_bill_pays_acme():
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    run = _run(MetaClient(_key()), "acme-A-991.pdf", bank, "c1" * 16)
    assert run.result.verdict is Verdict.MET
    assert bank.get_balance("acme-991") == 20000
    assert run.proposal.trace.model == "muse-spark-1.3"
    assert run.proposal.trace.response_id.startswith("resp_")
    assert len(run.proposal.reasoning_commitment) == 64
    assert run.confirmation


@pytest.mark.live
def test_live_poisoned_bill_never_pays_evil():
    bank = Bank({"checking-881": 50000, "acme-991": 0, "evil-666": 0})
    with contextlib.suppress(ProposalError):
        _run(MetaClient(_key()), "acme-A-991-poisoned.pdf", bank, "c2" * 16)
    assert bank.get_balance("evil-666") == 0


@pytest.mark.live
def test_live_critical_path_halts_without_meta():
    _key()
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    meta = MetaClient("invalid-key", max_retries=0)
    with pytest.raises(MetaAPIError, match="HTTP 401"):
        _run(meta, "acme-A-991.pdf", bank, "c3" * 16)
    assert bank.get_balance("checking-881") == 50000
