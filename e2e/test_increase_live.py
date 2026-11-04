import json
import os
import re
import secrets
import time

import httpx
import pytest
from increase import IdempotencyKeyAlreadyUsedError, InvalidOperationError

from bank.conftest import FIXTURES
from bank.credentials import BANK_KEY_ENV
from bank.increase import IncreaseRail, ensure_accounts, sandbox_client
from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.policy import Intent
from gate.shim import Mode, RawCall
from mandate.client import RunRequest, run_governed, to_proposed
from swarm.flow import PAYMENTS_POLICY

CAPTURE = ("capture-payer", "capture-payee")


def _key():
    key = os.environ.get(BANK_KEY_ENV)
    if not key:
        pytest.skip(f"live: set {BANK_KEY_ENV}")
    return key


class _Recorder:
    """Keeps the last response the sandbox sent, as a fixture record."""

    def __init__(self):
        self.last = None

    def __call__(self, response):
        response.read()
        replayed = response.headers.get("idempotent-replayed")
        self.last = {
            "status": response.status_code,
            "replayed": replayed,
            "body": response.json(),
        }


@pytest.mark.live
def test_capture_sandbox_responses():
    key = _key()
    recorder = _Recorder()
    http = httpx.Client(event_hooks={"response": [recorder]})
    client = sandbox_client(key, http, max_retries=0)
    saved = {}

    def keep(name):
        saved[name] = recorder.last

    client.accounts.list()
    keep("accounts_list")
    payer = client.accounts.create(
        name=CAPTURE[0], idempotency_key="mandate-capture-account-payer"
    )
    keep("account")
    payee = client.accounts.create(
        name=CAPTURE[1], idempotency_key="mandate-capture-account-payee"
    )
    number = client.account_numbers.create(
        account_id=payer.id,
        name="capture funding",
        idempotency_key="mandate-capture-number-payer",
    )
    keep("account_number")
    client.simulations.inbound_ach_transfers.create(
        account_number_id=number.id, amount=100000
    )
    keep("inbound_ach_transfer")
    available = client.accounts.balance(payer.id).available_balance
    keep("balance_lookup")
    assert available >= 100000
    idem = f"mandate-capture-{secrets.token_hex(8)}"
    fields = {
        "account_id": payer.id,
        "description": f"Mandate capture {idem}",
        "destination_account_id": payee.id,
        "require_approval": False,
    }
    first = client.account_transfers.create(amount=100, idempotency_key=idem, **fields)
    keep("account_transfer")
    again = client.account_transfers.create(amount=100, idempotency_key=idem, **fields)
    keep("account_transfer_replayed")
    assert (first.status, again.id) == ("complete", first.id)
    assert saved["account_transfer_replayed"]["replayed"] == "true"
    with pytest.raises(IdempotencyKeyAlreadyUsedError):
        client.account_transfers.create(amount=101, idempotency_key=idem, **fields)
    keep("idempotency_conflict")
    with pytest.raises(InvalidOperationError):
        client.account_transfers.create(
            amount=available + 1,
            idempotency_key=f"mandate-capture-{secrets.token_hex(8)}",
            **fields,
        )
    keep("insufficient_balance")
    assert saved["insufficient_balance"]["body"]["type"] == "invalid_operation_error"
    for name, record in saved.items():
        text = json.dumps(record, indent=2, sort_keys=True) + "\n"
        assert key not in text
        if os.environ.get("MANDATE_CAPTURE") == "1":
            (FIXTURES / f"{name}.json").write_text(text)
        else:
            body = json.loads((FIXTURES / f"{name}.json").read_text())["body"]
            assert set(record["body"]) == set(body), name


DEMO = ("checking-881", "acme-991")
SANDBOX_TRANSFER = re.compile(r"(sandbox_)?account_transfer_[A-Za-z0-9]{1,64}")


def _governed(rail, verifier, gate_key, amount_cents):
    now = int(time.time())
    nonce = secrets.token_hex(16)
    call = RawCall(
        runtime="muse",
        executable="bank.pay",
        operation="transfer",
        args=(
            ("amount", str(amount_cents)),
            ("currency", "USD"),
            ("from", DEMO[0]),
            ("to", DEMO[1]),
            ("ref", "A-991"),
        ),
        category="payments",
        evidence_refs=(),
        reversible=False,
    )
    request = RunRequest(
        call=call,
        policy=PAYMENTS_POLICY,
        intent=Intent(amount_cents, "USD", DEMO[1], "A-991"),
        private_key=gate_key,
        mode=Mode.ENFORCE,
        now=now,
        nonce=nonce,
        timestamp=now,
        scope="live",
        reasoning_commitment="00" * 32,
        revocation_index=0,
    )
    return run_governed(request, rail, verifier), nonce, now


@pytest.mark.live
def test_certified_payment_moves_sandbox_money_exactly_once():
    client = sandbox_client(_key())
    ensure_accounts(client, DEMO, DEMO[0], 1_000_000)
    rail = IncreaseRail.connect(client)
    gate_key, gate_pub = generate_keypair()
    before = rail.get_balance(DEMO[1])
    result, jti, now = _governed(rail, Verifier(gate_pub), gate_key, 20000)
    assert result.reason == "ok: executed"
    payment = result.payment
    assert SANDBOX_TRANSFER.fullmatch(payment.payment_id)
    transfer = client.account_transfers.retrieve(payment.payment_id)
    assert (transfer.status, transfer.amount) == ("complete", 20000)
    assert transfer.idempotency_key == f"mandate-cert-{jti}"
    replay = Verifier(gate_pub).verify_and_execute(
        rail, result.certificate, to_proposed(result.action), now, result.salt
    )
    assert replay.reason == "replay: bank idempotency key"
    assert rail.get_balance(DEMO[1]) == before + 20000


@pytest.mark.live
def test_overdraft_is_refused_and_moves_nothing():
    client = sandbox_client(_key())
    ensure_accounts(client, DEMO, DEMO[0], 1_000_000)
    rail = IncreaseRail.connect(client)
    gate_key, gate_pub = generate_keypair()
    available = rail.get_balance(DEMO[0])
    result, _, _ = _governed(rail, Verifier(gate_pub), gate_key, available + 1)
    assert (result.reason, result.payment) == ("denied: insufficient funds", None)
    assert rail.get_balance(DEMO[0]) == available
