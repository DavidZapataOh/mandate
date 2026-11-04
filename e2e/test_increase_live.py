import json
import os
import re
import secrets
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from increase import IdempotencyKeyAlreadyUsedError, InvalidOperationError

from bank.api import PaymentRequest
from bank.conftest import DOC_EVENT, FIXTURES
from bank.credentials import BANK_KEY_ENV
from bank.events import BankEvents
from bank.increase import IncreaseRail, ensure_accounts, sandbox_client
from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.consent import Consent, sign_approval
from gate.policy import Intent
from gate.shim import Mode, RawCall
from gate.state import StateStore
from mandate.client import RunRequest, run_governed, to_proposed
from swarm.desk import PaymentDesk
from swarm.flow import PAYMENTS_POLICY
from swarm.intent import sign_intent

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


@pytest.mark.live
def test_capture_reconcile_responses():
    key = _key()
    recorder = _Recorder()
    client = sandbox_client(
        key, httpx.Client(event_hooks={"response": [recorder]}), max_retries=0
    )
    payer = next(a for a in client.accounts.list() if a.name == CAPTURE[0])
    saved = {}
    listed = list(client.account_transfers.list(account_id=payer.id, limit=100))
    saved["account_transfers_list"] = recorder.last
    assert listed, "run test_capture_sandbox_responses first"
    known = listed[0].idempotency_key
    list(client.account_transfers.list(idempotency_key=known))
    saved["account_transfers_by_key"] = recorder.last
    list(client.account_transfers.list(idempotency_key="mandate-capture-none"))
    saved["account_transfers_none"] = recorder.last
    assert saved["account_transfers_none"]["body"]["data"] == []
    for name, record in saved.items():
        text = json.dumps(record, indent=2, sort_keys=True) + "\n"
        assert key not in text
        if os.environ.get("MANDATE_CAPTURE") == "1":
            (FIXTURES / f"{name}.json").write_text(text)
        else:
            body = json.loads((FIXTURES / f"{name}.json").read_text())["body"]
            assert set(record["body"]) == set(body), name


# Accounts of their own, so these transfers never reach the demo
# account's reconciliation.
LIVE = ("live-payer", "live-payee")
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
            ("from", LIVE[0]),
            ("to", LIVE[1]),
            ("ref", "A-991"),
        ),
        category="payments",
        evidence_refs=(),
        reversible=False,
    )
    request = RunRequest(
        call=call,
        policy=PAYMENTS_POLICY,
        intent=Intent(amount_cents, "USD", LIVE[1], "A-991"),
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
    ensure_accounts(client, LIVE, LIVE[0], 1_000_000)
    rail = IncreaseRail.connect(client)
    gate_key, gate_pub = generate_keypair()
    before = rail.get_balance(LIVE[1])
    result, jti, now = _governed(rail, Verifier(gate_pub), gate_key, 20000)
    assert result.reason == "ok: executed"
    payment = result.payment
    assert SANDBOX_TRANSFER.fullmatch(payment.payment_id)
    transfer = client.account_transfers.retrieve(payment.payment_id)
    assert (transfer.status, transfer.amount) == ("complete", 20000)
    assert transfer.idempotency_key == f"mandate-cert-{jti}"
    # A fresh verifier has not spent the jti, so the bank's replayed answer
    # is read as this certificate's own transfer: reported, never moved again.
    replay = Verifier(gate_pub).verify_and_execute(
        rail, result.certificate, to_proposed(result.action), now, result.salt
    )
    assert (replay.reason, replay.payment.payment_id) == (
        "ok: executed",
        payment.payment_id,
    )
    found = rail.reconcile(
        PaymentRequest(LIVE[0], LIVE[1], 20000, "USD", "A-991"),
        payment.action_hash,
        payment.idempotency_key,
    )
    assert found is not None and found.payment_id == payment.payment_id
    assert rail.get_balance(LIVE[1]) == before + 20000


@pytest.mark.live
def test_overdraft_is_refused_and_moves_nothing():
    client = sandbox_client(_key())
    ensure_accounts(client, LIVE, LIVE[0], 1_000_000)
    rail = IncreaseRail.connect(client)
    gate_key, gate_pub = generate_keypair()
    available = rail.get_balance(LIVE[0])
    result, _, _ = _governed(rail, Verifier(gate_pub), gate_key, available + 1)
    assert (result.reason, result.payment) == ("denied: insufficient funds", None)
    assert rail.get_balance(LIVE[0]) == available


@pytest.mark.live
def test_reconciler_names_every_live_transfer(tmp_path):
    client = sandbox_client(_key())
    ensure_accounts(client, LIVE, LIVE[0], 1_000_000)
    rail = IncreaseRail.connect(client)
    gate_key, gate_pub = generate_keypair()
    holder_key, holder_pub = generate_keypair()
    store = StateStore(tmp_path / "state.db")
    # The registry begins at the desk's clock in whole seconds; the next
    # second keeps earlier tests' transfers out of its list.
    time.sleep(1 - time.time() % 1)
    desk = PaymentDesk(
        source=LIVE[0],
        bank=rail,
        verifier=Verifier(gate_pub, state=store),
        gate_key=gate_key,
        clock=lambda: int(time.time()),
        nonces=lambda: secrets.token_hex(16),
        state=store,
    )
    desk.register_holder(holder_pub)
    intent = Intent(100, "USD", LIVE[1], "A-991")
    recorded = desk.record_intent(intent, sign_intent(holder_key, intent))
    assert recorded["status"] == "signed"
    quoted = desk.quote(LIVE[1], 100, "USD", "A-991", intent_id=recorded["intent_id"])
    consent = Consent(**quoted["consent"], signature=b"")
    desk.approve(quoted["quote_id"], sign_approval(holder_key, consent))
    paid = desk.confirm(quoted["quote_id"])
    assert (paid["status"], paid["reason"]) == ("confirmed", "ok: executed")
    report = desk.reconcile()
    assert (report.transfers, report.certified, report.unbacked, report.missing) == (
        1,
        1,
        (),
        (),
    )
    assert report.error is None
    store.close()


def _until(deadline_s, check):
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        found = check()
        if found:
            return found
        time.sleep(2)
    return None


@pytest.mark.live
def test_capture_bank_events(tmp_path):
    key = _key()
    recorder = _Recorder()
    client = sandbox_client(key, httpx.Client(event_hooks={"response": [recorder]}))
    since = (datetime.now(UTC) - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payer = client.accounts.create(
        name=CAPTURE[0], idempotency_key="mandate-capture-account-payer"
    )
    payee = client.accounts.create(
        name=CAPTURE[1], idempotency_key="mandate-capture-account-payee"
    )
    transfer = client.account_transfers.create(
        account_id=payer.id,
        amount=100,
        description="Mandate capture bank events",
        destination_account_id=payee.id,
        require_approval=False,
        idempotency_key=f"mandate-capture-{secrets.token_hex(8)}",
    )
    path = tmp_path / "state" / "state.db"
    store = StateStore(path)
    feed = BankEvents(client, store, since, lambda: int(time.time()))
    shown = []

    def reported():
        feed.poll(shown.append)
        return [e for e in shown if e.object_id == transfer.id]

    mine = _until(60, reported)
    assert mine, "the sandbox listed no event for the transfer within 60 s"
    assert mine[0].category == "account_transfer.created"
    record = recorder.last
    store.close()
    again = StateStore(path)
    repeat = []
    BankEvents(client, again, since, lambda: int(time.time())).poll(repeat.append)
    again.close()
    assert not {e.event_id for e in repeat} & {e.event_id for e in shown}
    text = json.dumps(record, indent=2, sort_keys=True) + "\n"
    assert key not in text
    if os.environ.get("MANDATE_CAPTURE") == "1":
        (FIXTURES / "events_page.json").write_text(text)
    for body in record["body"]["data"] or [DOC_EVENT]:
        assert set(body) == set(DOC_EVENT)
