import json
import os
import re
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from increase import (
    APIStatusError,
    IdempotencyKeyAlreadyUsedError,
    InvalidOperationError,
)

from bank.ach import simulate
from bank.api import PaymentRequest
from bank.card import ensure_card, ensure_card_subscription
from bank.conftest import DOC_EVENT, FIXTURES
from bank.credentials import BANK_KEY_ENV, WEBHOOK_SECRET_ENV
from bank.events import BankEvents
from bank.increase import (
    IncreaseRail,
    ensure_account_number,
    ensure_accounts,
    sandbox_client,
)
from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.consent import Consent, sign_approval
from gate.policy import Intent
from gate.shim import Mode, RawCall
from gate.state import StateStore
from mandate.client import RunRequest, run_governed, to_proposed
from swarm.card import CardAuthorizer, card_webhook_app, card_webhook_server
from swarm.conftest import DEMO_INTENT
from swarm.console_line import console_line_json
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


@pytest.mark.live
def test_capture_two_step_responses():
    key = _key()
    recorder = _Recorder()
    http = httpx.Client(event_hooks={"response": [recorder]})
    client = sandbox_client(key, http, max_retries=0)
    accounts = ensure_accounts(client, CAPTURE, CAPTURE[0], 100000)
    payer, payee = accounts[CAPTURE[0]], accounts[CAPTURE[1]]
    saved = {}

    def keep(name):
        saved[name] = recorder.last

    def hold():
        idem = f"mandate-capture-{secrets.token_hex(8)}"
        return client.account_transfers.create(
            account_id=payer,
            amount=100,
            description=f"Mandate capture {idem}",
            destination_account_id=payee,
            require_approval=True,
            idempotency_key=idem,
        )

    before = client.accounts.balance(payer).available_balance
    held = hold()
    keep("account_transfer_pending")
    assert (held.status, held.transaction_id) == ("pending_approval", None)
    assert held.pending_transaction_id is not None
    # A hold holds funds: the pending transaction lowers the available balance.
    assert client.accounts.balance(payer).available_balance == before - 100
    client.account_transfers.list(idempotency_key=held.idempotency_key)
    keep("account_transfers_held")
    approve = f"mandate-approve-{held.id}"
    done = client.account_transfers.approve(held.id, idempotency_key=approve)
    keep("account_transfer_approved")
    assert done.status == "complete"
    assert done.approval is not None and done.approval.approved_by is None
    again = client.account_transfers.approve(held.id, idempotency_key=approve)
    keep("account_transfer_approved_replayed")
    assert again.id == held.id
    assert saved["account_transfer_approved_replayed"]["replayed"] == "true"
    with pytest.raises(APIStatusError):
        client.account_transfers.approve(
            held.id, idempotency_key=f"mandate-approve-again-{held.id}"
        )
    keep("approve_not_pending")
    with pytest.raises(APIStatusError):
        client.account_transfers.cancel(
            held.id, idempotency_key=f"mandate-cancel-{held.id}"
        )
    keep("cancel_complete")
    second = hold()
    gone = client.account_transfers.cancel(
        second.id, idempotency_key=f"mandate-cancel-{second.id}"
    )
    keep("account_transfer_canceled")
    assert gone.status == "canceled" and gone.cancellation is not None
    # The approved 100 left; the canceled hold gave its 100 back.
    assert client.accounts.balance(payer).available_balance == before - 100
    with pytest.raises(APIStatusError):
        client.account_transfers.approve(
            second.id, idempotency_key=f"mandate-approve-{second.id}"
        )
    keep("approve_canceled")
    client.account_transfers.retrieve(second.id)
    keep("account_transfer_retrieved")
    for name, record in saved.items():
        text = json.dumps(record, indent=2, sort_keys=True) + "\n"
        assert key not in text
        if os.environ.get("MANDATE_CAPTURE") == "1":
            (FIXTURES / f"{name}.json").write_text(text)
        else:
            body = json.loads((FIXTURES / f"{name}.json").read_text())["body"]
            assert set(record["body"]) == set(body), name


@pytest.mark.live
def test_a_two_step_payment_waits_at_the_bank_until_the_certified_confirm(
    tmp_path,
):
    client = sandbox_client(_key())
    ensure_accounts(client, LIVE, LIVE[0], 1_000_000)
    rail = IncreaseRail.connect(client, two_step=True)
    gate_key, gate_pub = generate_keypair()
    holder_key, holder_pub = generate_keypair()
    store = StateStore(tmp_path / "state.db")
    time.sleep(1 - time.time() % 1)
    desk = PaymentDesk(
        source=LIVE[0],
        bank=rail,
        verifier=Verifier(gate_pub, state=store),
        gate_key=gate_key,
        clock=lambda: int(time.time()),
        nonces=lambda: secrets.token_hex(16),
        quote_ttl_s=10,
        state=store,
    )
    desk.register_holder(holder_pub)

    def held_quote(reference):
        intent = Intent(100, "USD", LIVE[1], reference)
        iid = desk.record_intent(intent, sign_intent(holder_key, intent))["intent_id"]
        quoted = desk.quote(LIVE[1], 100, "USD", reference, intent_id=iid)
        hold = json.loads(dict(store.records("hold"))[quoted["quote_id"]])
        return quoted, hold["transfer_id"]

    quoted, held = held_quote("A-991")
    assert client.account_transfers.retrieve(held).status == "pending_approval"
    consent = Consent(**quoted["consent"], signature=b"")
    desk.approve(quoted["quote_id"], sign_approval(holder_key, consent))
    paid = desk.confirm(quoted["quote_id"])
    assert (paid["status"], paid["payment_id"]) == ("confirmed", held)
    done = client.account_transfers.retrieve(held)
    assert done.status == "complete" and done.approval is not None
    assert done.approval.approved_by is None
    bank = desk.proof_receipt(held)
    assert bank is not None
    expired, dropped = held_quote("A-992")
    time.sleep(11)
    report = desk.reconcile()
    assert f"{expired['quote_id']} -> hold canceled" in report.resolved
    assert client.account_transfers.retrieve(dropped).status == "canceled"
    assert (report.unbacked, report.error) == ((), None)
    store.close()


@pytest.mark.live
def test_capture_ach_responses():
    key = _key()
    recorder = _Recorder()
    http = httpx.Client(event_hooks={"response": [recorder]})
    client = sandbox_client(key, http, max_retries=0)
    accounts = ensure_accounts(client, CAPTURE, CAPTURE[0], 100000)
    payer, payee = accounts[CAPTURE[0]], accounts[CAPTURE[1]]
    saved = {}

    def keep(name):
        saved[name] = recorder.last

    number = client.account_numbers.create(
        account_id=payee,
        name=f"{CAPTURE[1]} ach",
        idempotency_key="mandate-capture-ach-number-payee",
    )
    client.account_numbers.list(account_id=payee, status={"in": ["active"]})
    keep("account_numbers_active")
    idem = f"mandate-capture-{secrets.token_hex(8)}"
    fields = {
        "account_id": payer,
        "statement_descriptor": f"Mandate capture {idem}",
        "account_number": number.account_number,
        "routing_number": number.routing_number,
        "funding": "checking",
        "individual_name": CAPTURE[1],
        "require_approval": False,
    }
    before = client.accounts.balance(payer).available_balance
    sent = client.ach_transfers.create(amount=100, idempotency_key=idem, **fields)
    keep("ach_transfer")
    assert sent.status == "pending_submission"
    # The bank holds the amount at once: a pending transaction.
    assert client.accounts.balance(payer).available_balance == before - 100
    again = client.ach_transfers.create(amount=100, idempotency_key=idem, **fields)
    keep("ach_transfer_replayed")
    assert again.id == sent.id
    assert saved["ach_transfer_replayed"]["replayed"] == "true"
    with pytest.raises(IdempotencyKeyAlreadyUsedError):
        client.ach_transfers.create(amount=101, idempotency_key=idem, **fields)
    keep("ach_idempotency_conflict")
    client.ach_transfers.list(idempotency_key=idem)
    keep("ach_transfers_by_key")
    with pytest.raises(APIStatusError):
        client.simulations.ach_transfers.return_(
            sent.id,
            reason="insufficient_fund",
            idempotency_key=f"mandate-capture-early-return-{sent.id}",
        )
    keep("ach_return_refused")
    client.simulations.ach_transfers.submit(
        sent.id, idempotency_key=f"mandate-simulate-submit-{sent.id}"
    )
    keep("ach_transfer_submitted")
    settled = client.simulations.ach_transfers.settle(
        sent.id, idempotency_key=f"mandate-simulate-settle-{sent.id}"
    )
    keep("ach_transfer_settled")
    assert settled.status == "submitted" and settled.settlement is not None
    returned = client.simulations.ach_transfers.return_(
        sent.id,
        reason="insufficient_fund",
        idempotency_key=f"mandate-simulate-return-{sent.id}",
    )
    keep("ach_transfer_returned")
    assert returned.status == "returned" and returned.return_ is not None
    assert returned.return_.raw_return_reason_code == "R01"
    # The return offsets the original: the 100 is back.
    assert client.accounts.balance(payer).available_balance == before
    client.ach_transfers.retrieve(sent.id)
    keep("ach_transfer_retrieved")
    available = client.accounts.balance(payer).available_balance
    with pytest.raises(InvalidOperationError):
        client.ach_transfers.create(
            amount=available + 1,
            idempotency_key=f"mandate-capture-{secrets.token_hex(8)}",
            **fields,
        )
    keep("ach_insufficient_balance")
    for name, record in saved.items():
        text = json.dumps(record, indent=2, sort_keys=True) + "\n"
        assert key not in text
        if os.environ.get("MANDATE_CAPTURE") == "1":
            (FIXTURES / f"{name}.json").write_text(text)
        else:
            body = json.loads((FIXTURES / f"{name}.json").read_text())["body"]
            assert set(record["body"]) == set(body), name


@pytest.mark.live
def test_an_ach_payment_settles_is_returned_and_the_registry_says_so(tmp_path):
    client = sandbox_client(_key())
    accounts = ensure_accounts(client, LIVE, LIVE[0], 1_000_000)
    ensure_account_number(client, accounts[LIVE[1]], LIVE[1])
    rail = IncreaseRail.connect(client, ach=True)
    gate_key, gate_pub = generate_keypair()
    holder_key, holder_pub = generate_keypair()
    store = StateStore(tmp_path / "state.db")
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
    intent = Intent(100, "USD", LIVE[1], "A-ACH")
    iid = desk.record_intent(intent, sign_intent(holder_key, intent))["intent_id"]
    quoted = desk.quote(LIVE[1], 100, "USD", "A-ACH", intent_id=iid)
    consent = Consent(**quoted["consent"], signature=b"")
    desk.approve(quoted["quote_id"], sign_approval(holder_key, consent))
    paid = desk.confirm(quoted["quote_id"])
    pid = paid["payment_id"]
    assert paid["status"] == "confirmed"
    assert pid.startswith(("ach_transfer_", "sandbox_ach_transfer_"))
    simulate(client, "settle", pid)
    assert desk.track_ach(pid) == "settled"
    simulate(client, "return", pid)
    report = desk.reconcile()
    assert f"{pid} -> returned R01 (SIMULATED RETURN)" in report.resolved
    assert desk.intent_receipt(iid)["status"] == "returned"
    assert desk.lifecycle(pid)["label"] == "SIMULATED RETURN"
    assert desk.reconcile().resolved == ()
    store.close()


CARD_CATEGORY = "real_time_decision.card_authorization_requested"
CAPTURE_PORT = 8788


def _card_env():
    secret = os.environ.get(WEBHOOK_SECRET_ENV)
    url = os.environ.get("MANDATE_CARD_WEBHOOK_URL")
    if not secret or not url:
        pytest.skip("live: set the webhook secret and MANDATE_CARD_WEBHOOK_URL")
    return secret, url


def _point_subscription(client, url, secret):
    for sub in client.event_subscriptions.list():
        cats = [c.event_category for c in sub.selected_event_categories or []]
        if sub.status == "active" and CARD_CATEGORY in cats:
            client.event_subscriptions.update(sub.id, status="deleted")
    return client.event_subscriptions.create(
        url=url,
        selected_event_categories=[{"event_category": CARD_CATEGORY}],
        shared_secret=secret,
        idempotency_key=f"mandate-capture-rtd-{secrets.token_hex(8)}",
    )


@pytest.mark.live
def test_capture_card_authorization():
    key = _key()
    secret, url = _card_env()
    recorder = _Recorder()
    http = httpx.Client(event_hooks={"response": [recorder]})
    client = sandbox_client(key, http, max_retries=0)
    answering = sandbox_client(key, max_retries=0)
    accounts = ensure_accounts(client, CAPTURE, CAPTURE[0], 100000)
    saved = {}

    def keep(name):
        saved[name] = recorder.last

    card = client.cards.create(
        account_id=accounts[CAPTURE[0]],
        description="mandate-capture-card",
        idempotency_key="mandate-capture-card",
    )
    keep("card")
    subscription = _point_subscription(client, url, secret)
    keep("event_subscription")
    plan = iter(["approve", "decline", "silent", "late"])
    heard = []
    answered_late = threading.Event()

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["content-length"]))
            event = answering.events.unwrap(
                body.decode(), headers=dict(self.headers), key=secret.encode()
            )
            decision_id = event.associated_object_id
            read = answering.real_time_decisions.with_raw_response.retrieve(decision_id)
            heard.append({"event": json.loads(body), "pending": read.json()})
            step = next(plan)
            if step == "silent":
                time.sleep(5)
            elif step == "late":
                # An approve that reaches the bank after its own deadline.
                due = datetime.fromisoformat(read.json()["timeout_at"])
                time.sleep(max(0.0, (due - datetime.now(UTC)).total_seconds()) + 1)
                try:
                    late = answering.real_time_decisions.with_raw_response.action(
                        decision_id,
                        card_authorization={"decision": "approve"},
                        idempotency_key=f"mandate-capture-{decision_id}",
                    )
                    heard[-1]["late"] = (late.status_code, late.json())
                except APIStatusError as exc:
                    heard[-1]["late"] = (exc.status_code, None)
                answered_late.set()
            else:
                answer = {"decision": step}
                if step == "decline":
                    answer["decline"] = {"reason": "transaction_never_allowed"}
                done = answering.real_time_decisions.with_raw_response.action(
                    decision_id,
                    card_authorization=answer,
                    idempotency_key=f"mandate-capture-{decision_id}",
                )
                heard[-1]["answered"] = done.json()
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", CAPTURE_PORT), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    charge = {
        "amount": 100,
        "card_id": card.id,
        "merchant_acceptor_id": "acme-991",
        "merchant_descriptor": "ACME 991",
    }
    try:
        approved = client.simulations.card_authorizations.create(**charge)
        keep("card_authorization_simulation")
        declined = client.simulations.card_authorizations.create(**charge)
        keep("card_authorization_declined")
        silent = client.simulations.card_authorizations.create(**charge)
        after = client.real_time_decisions.retrieve(
            heard[2]["event"]["associated_object_id"]
        )
        keep("real_time_decision_timed_out")
        late = client.simulations.card_authorizations.create(**charge)
        # The bank gives up before the late approve is sent; wait for it.
        assert answered_late.wait(10)
        late_after = client.real_time_decisions.retrieve(
            heard[3]["event"]["associated_object_id"]
        )
    finally:
        server.shutdown()
        client.event_subscriptions.update(subscription.id, status="deleted")
    # The simulation answers only after the bank heard Mandate (or timed out).
    assert approved.pending_transaction is not None
    reasons = [
        r.declined_transaction.source.card_decline.reason for r in (declined, silent)
    ]
    assert reasons == ["webhook_declined", "webhook_timed_out"]
    assert after.status == "timed_out"
    # A late approve is refused by the bank, so a slow answer never pays.
    late_status, late_body = heard[3]["late"]
    assert late_status >= 400 or late_body["status"] == "timed_out"
    assert late.declined_transaction is not None
    assert late.declined_transaction.source.card_decline.reason == "webhook_timed_out"
    assert late_after.status == "timed_out"
    first = heard[0]["pending"]
    assert first["status"] == "pending"
    assert first["card_authorization"]["merchant_acceptor_id"] == "acme-991"
    window = datetime.fromisoformat(first["timeout_at"]) - datetime.fromisoformat(
        first["created_at"]
    )
    assert window.total_seconds() <= 4.0
    assert heard[0]["answered"]["card_authorization"]["decision"] == "approve"
    assert heard[1]["answered"]["card_authorization"]["decision"] == "decline"
    for name, part, field in (
        ("real_time_decision_pending", 0, "pending"),
        ("real_time_decision_approved", 0, "answered"),
        ("real_time_decision_declined", 1, "answered"),
        ("card_webhook_event", 0, "event"),
    ):
        saved[name] = {"status": 200, "replayed": None, "body": heard[part][field]}
    for name, record in saved.items():
        text = json.dumps(record, indent=2, sort_keys=True) + "\n"
        assert key not in text and secret not in text
        if os.environ.get("MANDATE_CAPTURE") == "1":
            (FIXTURES / f"{name}.json").write_text(text)
        else:
            body = json.loads((FIXTURES / f"{name}.json").read_text())["body"]
            assert set(record["body"]) == set(body), name


def _card_lines(lines):
    return [line.subject for line in lines if line.subject.get("step") == "card"]


@pytest.mark.live
def test_card_authorization_end_to_end(tmp_path):
    key = _key()
    secret, url = _card_env()
    client = sandbox_client(key)
    accounts = ensure_accounts(client, CAPTURE, CAPTURE[0], 1_000_000)
    gate_key, gate_pub = generate_keypair()
    holder_key, holder_pub = generate_keypair()
    store = StateStore(tmp_path / "state.db")
    lines = []
    desk = PaymentDesk(
        source=CAPTURE[0],
        bank=IncreaseRail.connect(client),
        verifier=Verifier(gate_pub, state=store),
        gate_key=gate_key,
        clock=lambda: int(time.time()),
        nonces=lambda: secrets.token_hex(16),
        publish=lines.append,
        state=store,
    )
    desk.register_holder(holder_pub)
    signed = sign_intent(holder_key, DEMO_INTENT)
    iid = desk.record_intent(DEMO_INTENT, signed)["intent_id"]
    quoted = desk.quote("acme-991", 20000, "USD", "A-991", intent_id=iid)
    consent = Consent(**quoted["consent"], signature=b"")
    desk.approve(quoted["quote_id"], sign_approval(holder_key, consent))
    card_id = ensure_card(client, accounts[CAPTURE[0]], CAPTURE[0])
    authorizer = CardAuthorizer(client, desk, card_id, accounts[CAPTURE[0]], store)
    server = card_webhook_server(
        card_webhook_app(client, authorizer, secret), CAPTURE_PORT
    )
    serving = threading.Thread(target=server.run, daemon=True)
    serving.start()
    end = time.monotonic() + 10
    while not server.started and time.monotonic() < end:
        time.sleep(0.05)
    assert server.started
    charge = {
        "amount": 20000,
        "card_id": card_id,
        "merchant_acceptor_id": "acme-991",
        "merchant_descriptor": "ACME 991",
    }
    try:
        ensure_card_subscription(client, url, secret)
        approved = client.simulations.card_authorizations.create(**charge)
        again = client.simulations.card_authorizations.create(**charge)
    finally:
        server.should_exit = True
        serving.join(10)
    assert approved.pending_transaction is not None
    paid = approved.pending_transaction.source.card_authorization
    decision_id = paid.real_time_decision_id
    entries = [desk.registry.entry(n) for n in range(1, desk.registry.size() + 1)]
    sealed = [json.loads(e.body) for e in entries if e.kind == "execution"]
    assert [entry["payment_id"] for entry in sealed] == [decision_id]
    assert desk.status(quoted["quote_id"])["status"] == "confirmed"
    assert again.declined_transaction is not None
    refused = again.declined_transaction.source.card_decline
    assert refused.reason == "webhook_declined"
    answers = _card_lines(lines)
    assert [(a["status"], a["payment_id"]) for a in answers] == [
        ("approved", decision_id),
        ("declined", refused.real_time_decision_id),
    ]
    assert answers[1]["reason"] == "card: no approved quote"
    published = "".join(console_line_json(line) for line in lines)
    assert key not in published and secret not in published
    store.close()
