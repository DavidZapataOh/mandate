import dataclasses
import json

import pytest

from bank.api import PaymentRequest, RailError, ReplayError
from bank.conftest import Cassette, RecordingRail, recorded
from bank.increase import IncreaseRail
from bank.reconcile import CANCELED, PENDING_APPROVAL, BankTransfer
from bank.test_increase import ACCOUNTS
from gate.consent import Consent, sign_approval
from gate.policy import Intent
from gate.state import StateStore
from swarm.conftest import DEMO_INTENT
from swarm.intent import sign_intent
from swarm.test_desk_state import (
    HOLDER,
    NOW,
    _approve_and_confirm,
    _desk,
    _restart,
)

KEY = "mandate-cert-00000000000000000000000000000002"
HELD = "account_transfer_h1"
REQUEST = PaymentRequest("checking-881", "acme-991", 20000, "USD", "A-991")


def _two_step(store, now=None, **rail):
    bank = RecordingRail(balance=50000, two_step=True, **rail)
    desk = _desk(store, bank=bank, now=now)
    desk.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))
    return desk, bank


def _quote(desk):
    return desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")


def _holds(store):
    return {k: json.loads(v) for k, v in store.records("hold")}


def test_a_quote_holds_the_amount_at_the_bank_under_its_certificate_key(
    state_store,
):
    desk, rail = _two_step(state_store)
    assert _quote(desk)["status"] == "quoted"
    assert rail.holds == [(REQUEST, KEY)]
    assert _holds(state_store) == {
        "q:000001": {
            "intent_id": "i:000001",
            "idempotency_key": KEY,
            "transfer_id": HELD,
            "expires_at": NOW + 600,
            "rail": "sandbox",
        }
    }


def test_confirm_approves_the_hold_once_under_the_same_key(state_store):
    desk, rail = _two_step(state_store)
    q = _quote(desk)
    done = _approve_and_confirm(desk, q)
    assert (done["status"], done["payment_id"]) == ("confirmed", HELD)
    assert desk.confirm(q["quote_id"]) == done
    assert [call[2] for call in rail.calls] == [KEY]
    receipt = desk.proof_receipt(HELD)
    assert receipt is not None and receipt["payment_id"] == HELD
    assert _holds(state_store) == {}


def test_a_quote_without_an_intent_holds_nothing(state_store):
    desk, rail = _two_step(state_store)
    assert desk.quote("acme-991", 20000, "USD", "A-991") == {
        "status": "denied",
        "reason": "intent: missing",
        "intent_id": None,
    }
    assert rail.holds == []


def test_an_intent_holds_at_most_once(state_store):
    desk, rail = _two_step(state_store)
    _quote(desk)
    assert _quote(desk) == {
        "status": "denied",
        "reason": "intent: held at the bank",
        "intent_id": "i:000001",
    }
    assert len(rail.holds) == 1


@pytest.mark.parametrize(
    ("error", "reason", "kept"),
    [
        (RailError("bank: unavailable"), "bank: unavailable", False),
        (RailError("bank: refused"), "bank: refused", False),
        (
            ValueError("insufficient funds: checking-881"),
            "denied: insufficient funds",
            False,
        ),
        (RailError("bank: outcome unknown"), "bank: outcome unknown", True),
        (RailError("bank: not held for approval"), "bank: not held for approval", True),
    ],
)
def test_a_hold_the_bank_refuses_denies_the_quote(state_store, error, reason, kept):
    desk, rail = _two_step(state_store, hold_error=error)
    assert _quote(desk) == {
        "status": "denied",
        "reason": reason,
        "intent_id": "i:000001",
    }
    assert list(_holds(state_store)) == (["q:000001"] if kept else [])
    rail.hold_error = None
    again = _quote(desk)
    assert again["status"] == ("denied" if kept else "quoted")
    assert again.get("reason", "") == ("intent: held at the bank" if kept else "")


def test_a_hold_canceled_at_the_bank_is_a_clean_denial(state_store):
    desk, rail = _two_step(state_store)
    q = _quote(desk)
    rail.error = RailError("bank: canceled at the bank")
    assert _approve_and_confirm(desk, q) == {
        "status": "denied",
        "quote_id": "q:000001",
        "reason": "bank: canceled at the bank",
        "payment_id": None,
    }
    assert desk.intent_receipt("i:000001")["status"] == "signed"
    assert state_store.records("pending") == []
    assert list(_holds(state_store)) == ["q:000001"]


def test_a_hold_approved_outside_the_gate_leaves_the_intent_unsettled(state_store):
    desk, rail = _two_step(state_store)
    q = _quote(desk)
    rail.error = RailError("bank: approved outside the gate")
    assert _approve_and_confirm(desk, q)["reason"] == "bank: approved outside the gate"
    view = desk.intent_receipt("i:000001")
    assert (view["status"], view["idempotency_key"]) == ("unsettled", KEY)
    assert [k for k, _ in state_store.records("pending")] == ["q:000001"]
    assert list(_holds(state_store)) == ["q:000001"]


@pytest.mark.parametrize(
    ("error", "reason", "kept"),
    [
        (
            ValueError("unknown account: acme-991"),
            "denied: unknown account",
            False,
        ),
        (ReplayError(KEY), "replay: bank idempotency key", True),
        (RailError("bank: transfer differs"), "bank: transfer differs", True),
        (TimeoutError("read timed out"), "bank: outcome unknown", True),
    ],
)
def test_every_other_hold_failure_denies_the_quote(state_store, error, reason, kept):
    desk, rail = _two_step(state_store, hold_error=error)
    assert _quote(desk)["reason"] == reason
    assert list(_holds(state_store)) == (["q:000001"] if kept else [])


def test_a_quote_whose_hold_failed_can_never_pay(state_store):
    desk, rail = _two_step(state_store, hold_error=RailError("bank: unavailable"))
    _quote(desk)
    assert desk.pending() == []
    assert desk.status("q:000001")["status"] == "denied"
    rail.hold_error = None
    q = _quote(desk)
    done = _approve_and_confirm(desk, q)
    assert (done["quote_id"], done["status"]) == ("q:000002", "confirmed")
    assert [call[2] for call in rail.calls] == [
        "mandate-cert-00000000000000000000000000000004"
    ]


def test_an_intent_that_already_paid_holds_nothing_more(state_store):
    desk, rail = _two_step(state_store)
    _approve_and_confirm(desk, _quote(desk))
    assert _quote(desk) == {
        "status": "denied",
        "reason": "intent: already used",
        "intent_id": "i:000001",
    }
    assert len(rail.holds) == 1


@pytest.mark.parametrize(
    ("unanswered", "two_step"), [(False, True), (False, False), (True, True)]
)
def test_a_restarted_desk_keeps_refusing_an_intent_held_at_the_bank(
    state_store, unanswered, two_step
):
    desk, rail = _two_step(state_store)
    _quote(desk)
    if unanswered:
        # The record as written before the bank call that never answered.
        hold = dict(_holds(state_store)["q:000001"], transfer_id=None)
        state_store.put_record("hold", "q:000001", json.dumps(hold))
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    try:
        bank = rail if two_step else RecordingRail(balance=50000)
        again = _desk(store, nonce_from=101, bank=bank)
        assert _quote(again)["reason"] == "intent: held at the bank"
        assert len(rail.holds) == 1
    finally:
        store.close()


def test_a_quote_denied_at_hold_stays_denied_after_a_restart(state_store):
    desk, rail = _two_step(state_store, hold_error=RailError("bank: outcome unknown"))
    _quote(desk)
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    try:
        again = _desk(store, nonce_from=101, bank=rail)
        assert again.status("q:000001") == {
            "status": "denied",
            "quote_id": "q:000001",
            "reason": "bank: outcome unknown",
            "payment_id": None,
        }
    finally:
        store.close()


@pytest.mark.parametrize(
    "fields",
    [
        ("acme-991", 20001, "USD", "A-991"),
        ("acme-991", 20000, "EUR", "A-991"),
        ("acme-992", 20000, "USD", "A-991"),
        ("acme-991", 20000, "USD", "A-992"),
    ],
)
def test_a_quote_that_differs_from_its_intent_holds_nothing(state_store, fields):
    desk, rail = _two_step(state_store)
    assert desk.quote(*fields, intent_id="i:000001") == {
        "status": "denied",
        "reason": "intent: differs",
        "intent_id": "i:000001",
    }
    assert rail.holds == []
    assert _holds(state_store) == {}


@pytest.mark.parametrize(
    "value",
    [
        "not json",
        json.dumps([1]),
        json.dumps({"intent_id": "i:000001"}),
        json.dumps(
            {
                "intent_id": "i:000001",
                "idempotency_key": KEY,
                "transfer_id": 7,
                "expires_at": NOW + 600,
                "rail": "sandbox",
            }
        ),
    ],
)
def test_a_corrupt_hold_record_stops_the_start(state_store, value):
    _desk(state_store)
    state_store.put_record("hold", "q:000001", value)
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    try:
        with pytest.raises(ValueError, match="^state: store unreadable$"):
            _desk(store)
    finally:
        store.close()


# The certificate expires 300 s after the confirm at NOW; the margin is 60 s.
CERT_RELEASE = NOW + 300 + 60


def _completed(rail):
    rail.listed[0] = dataclasses.replace(rail.listed[0], status="complete")


def test_an_open_hold_is_not_a_transfer_without_a_certificate(state_store):
    desk, rail = _two_step(state_store)
    _quote(desk)
    report = desk.reconcile()
    assert (report.transfers, report.unbacked, report.error) == (0, (), None)
    assert rail.releases == []


@pytest.mark.parametrize(("later", "canceled"), [(NOW + 600, False), (NOW + 601, True)])
def test_an_expired_quote_cancels_its_hold(state_store, later, canceled):
    now = [NOW]
    desk, rail = _two_step(state_store, now=now)
    _quote(desk)
    now[0] = later
    report = desk.reconcile()
    assert rail.releases == ([KEY] if canceled else [])
    assert report.resolved == (("q:000001 -> hold canceled",) if canceled else ())
    assert list(_holds(state_store)) == ([] if canceled else ["q:000001"])
    if canceled:
        assert _quote(desk)["status"] == "quoted"
        assert rail.holds[1][1] == "mandate-cert-00000000000000000000000000000004"


def test_a_denied_confirm_cancels_its_hold_in_the_next_round(state_store):
    desk, rail = _two_step(state_store)
    q = _quote(desk)
    rail.error = RailError("bank: refused")
    assert _approve_and_confirm(desk, q)["reason"] == "bank: refused"
    report = desk.reconcile()
    assert report.resolved == ("q:000001 -> hold canceled",)
    assert rail.releases == [KEY]


@pytest.mark.parametrize("later", [CERT_RELEASE - 1, CERT_RELEASE])
def test_a_hold_with_a_live_certificate_waits_for_its_expiry(state_store, later):
    now = [NOW]
    desk, rail = _two_step(state_store, now=now)
    q = _quote(desk)
    rail.error = RailError("bank: not complete")
    _approve_and_confirm(desk, q)
    now[0] = later
    report = desk.reconcile()
    if later < CERT_RELEASE:
        assert (rail.releases, report.pending) == ([], ("q:000001",))
        return
    assert rail.releases == [KEY]
    assert report.resolved == (
        "q:000001 -> hold canceled",
        "q:000001 -> not paid",
    )
    assert desk.intent_receipt("i:000001")["status"] == "signed"


def test_a_restart_cancels_every_hold_no_certificate_can_approve(state_store):
    desk, rail = _two_step(state_store)
    _quote(desk)
    again, store = _restart(state_store, bank=rail)
    report = again.reconcile()
    assert report.resolved == ("q:000001 -> hold canceled",)
    assert (rail.releases, rail.calls) == ([KEY], [])
    assert store.records("hold") == []
    store.close()


def test_a_lost_approval_the_bank_completed_is_sealed_once(state_store):
    desk, rail = _two_step(state_store)
    q = _quote(desk)
    rail.error = RailError("bank: outcome unknown")
    _approve_and_confirm(desk, q)
    rail.error = None
    _completed(rail)
    report = desk.reconcile()
    assert report.resolved == ("q:000001 -> account_transfer_h1",)
    assert (report.transfers, report.certified, report.unbacked) == (1, 1, ())
    assert (rail.releases, state_store.records("hold")) == ([], [])
    assert desk.reconcile().resolved == ()


def test_a_journal_approved_outside_the_gate_is_never_sealed(state_store):
    now = [NOW]
    desk, rail = _two_step(state_store, now=now)
    q = _quote(desk)
    rail.error = RailError("bank: approved outside the gate")
    _approve_and_confirm(desk, q)
    _completed(rail)
    rail.found = RailError("bank: approved outside the gate")
    now[0] = CERT_RELEASE + 40
    report = desk.reconcile()
    assert (report.error, report.resolved, report.pending) == (
        None,
        (),
        ("q:000001",),
    )
    assert report.unbacked == (HELD,)
    assert desk.intent_receipt("i:000001")["status"] == "unsettled"
    assert (rail.releases, list(_holds(state_store))) == ([KEY], ["q:000001"])
    assert _quote(desk)["reason"] == "intent: held at the bank"


def test_a_hold_the_bank_completed_without_a_certificate_stays_and_is_unbacked(
    state_store,
):
    now = [NOW]
    desk, rail = _two_step(state_store, now=now)
    _quote(desk)
    _completed(rail)
    now[0] = NOW + 601
    report = desk.reconcile()
    assert (rail.releases, report.unbacked) == ([KEY], (HELD,))
    assert list(_holds(state_store)) == ["q:000001"]
    assert _quote(desk)["reason"] == "intent: held at the bank"


def test_an_unreachable_bank_keeps_every_hold(state_store):
    now = [NOW]
    desk, rail = _two_step(state_store, now=now)
    _quote(desk)
    rail.release_error = RailError("bank: unavailable")
    now[0] = NOW + 601
    report = desk.reconcile()
    assert (report.error, report.resolved) == ("bank: unavailable", ())
    assert list(_holds(state_store)) == ["q:000001"]


class _OutsideFor(RecordingRail):
    """A rail whose lookup of one key finds a dashboard approval."""

    def reconcile(self, request, action_hash, idempotency_key):
        if idempotency_key == KEY:
            self.lookups.append((request, action_hash, idempotency_key))
            raise RailError("bank: approved outside the gate")
        return super().reconcile(request, action_hash, idempotency_key)


def test_a_dashboard_approval_does_not_stop_the_next_journal(state_store):
    rail = _OutsideFor(balance=50000, two_step=True)
    desk = _desk(state_store, bank=rail)
    desk.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))
    other = Intent(20000, "USD", "acme-991", "A-992")
    desk.record_intent(other, sign_intent(HOLDER, other))
    first = _quote(desk)
    second = desk.quote("acme-991", 20000, "USD", "A-992", intent_id="i:000002")
    rail.error = RailError("bank: approved outside the gate")
    _approve_and_confirm(desk, first)
    rail.error = RailError("bank: outcome unknown")
    _approve_and_confirm(desk, second)
    rail.error = None
    rail.listed = [dataclasses.replace(t, status="complete") for t in rail.listed]
    report = desk.reconcile()
    assert (report.error, report.resolved, report.pending) == (
        None,
        ("q:000002 -> account_transfer_h2",),
        ("q:000001",),
    )
    assert report.unbacked == (HELD,)


@pytest.mark.parametrize(("later", "dropped"), [(NOW + 659, False), (NOW + 660, True)])
def test_a_hold_the_bank_never_made_is_dropped_after_its_window(
    state_store, later, dropped
):
    now = [NOW]
    desk, rail = _two_step(
        state_store, now=now, hold_error=RailError("bank: outcome unknown")
    )
    _quote(desk)
    now[0] = later
    report = desk.reconcile()
    assert rail.releases == [KEY]
    assert report.resolved == (("q:000001 -> no hold at the bank",) if dropped else ())
    assert list(_holds(state_store)) == ([] if dropped else ["q:000001"])


def test_a_journal_sealed_not_paid_frees_its_intent_of_the_hold(state_store):
    now = [NOW]
    desk, rail = _two_step(state_store, now=now)
    q = _quote(desk)
    rail.error = RailError("bank: not complete")
    _approve_and_confirm(desk, q)
    rail.listed.clear()
    now[0] = CERT_RELEASE
    report = desk.reconcile()
    assert report.resolved == ("q:000001 -> not paid",)
    assert _holds(state_store) == {}
    rail.error = None
    assert _quote(desk)["status"] == "quoted"


def test_the_hold_of_a_confirmed_quote_is_dropped_without_the_bank(state_store):
    desk, rail = _two_step(state_store)
    _approve_and_confirm(desk, _quote(desk))
    hold = {
        "intent_id": "i:000001",
        "idempotency_key": KEY,
        "transfer_id": HELD,
        "expires_at": NOW + 600,
        "rail": "sandbox",
    }
    state_store.put_record("hold", "q:000001", json.dumps(hold))
    again, store = _restart(state_store, bank=rail)
    report = again.reconcile()
    assert (report.resolved, rail.releases) == ((), [])
    assert store.records("hold") == []
    store.close()


FOREIGN = "mandate-cert-00000000000000000000000000000099"


@pytest.mark.parametrize("released", [False, True])
def test_a_pending_transfer_under_a_key_the_desk_does_not_hold_is_unbacked(
    state_store, released
):
    now = [NOW]
    desk, rail = _two_step(state_store, now=now)
    _quote(desk)
    if released:
        now[0] = NOW + 601
        assert desk.reconcile().resolved == ("q:000001 -> hold canceled",)
        key, unheld = KEY, "account_transfer_h9"
    else:
        key, unheld = FOREIGN, "account_transfer_x9"
    rail.listed.append(BankTransfer(unheld, 500, PENDING_APPROVAL, key, ""))
    report = desk.reconcile()
    assert (report.transfers, report.unbacked, report.error) == (1, (unheld,), None)


class _SettledMeanwhile(RecordingRail):
    """A rail whose cancel races the holder's own lookup of the intent."""

    desk = None

    def release(self, idempotency_key, transfer_id=None):
        self.releases.append(idempotency_key)
        self.listed.clear()
        self.desk.reconcile_intent("i:000001")
        return CANCELED


def test_a_hold_settled_while_the_bank_answers_is_left_alone(state_store):
    now = [NOW]
    rail = _SettledMeanwhile(balance=50000, two_step=True)
    desk = _desk(state_store, bank=rail, now=now)
    desk.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))
    rail.desk = desk
    q = _quote(desk)
    rail.error = RailError("bank: not complete")
    _approve_and_confirm(desk, q)
    now[0] = CERT_RELEASE
    report = desk.reconcile()
    assert (report.error, report.resolved, rail.releases) == (None, (), [KEY])
    assert _holds(state_store) == {}
    assert desk.intent_receipt("i:000001")["status"] == "signed"


def test_a_completed_hold_due_for_release_is_sealed_in_the_same_round(state_store):
    now = [NOW]
    desk, rail = _two_step(state_store, now=now)
    q = _quote(desk)
    rail.error = RailError("bank: outcome unknown")
    _approve_and_confirm(desk, q)
    rail.error = None
    _completed(rail)
    now[0] = CERT_RELEASE
    report = desk.reconcile()
    assert rail.releases == [KEY]
    assert report.resolved == ("q:000001 -> account_transfer_h1",)
    assert _holds(state_store) == {}


def test_an_unpaired_holders_hold_is_canceled_after_the_refused_confirm(
    state_store,
):
    desk, rail = _two_step(state_store)
    q = _quote(desk)
    desk.approve(
        q["quote_id"], sign_approval(HOLDER, Consent(**q["consent"], signature=b""))
    )
    assert desk.unpair_holder(desk.paired_holders()[0][0])
    assert desk.confirm(q["quote_id"])["reason"] == "holder: unpaired"
    report = desk.reconcile()
    assert (report.resolved, rail.releases) == (("q:000001 -> hold canceled",), [KEY])


@pytest.mark.parametrize("held", [True, False])
def test_a_hold_is_released_by_the_id_the_bank_answered(state_store, held):
    now = [NOW]
    error = None if held else RailError("bank: outcome unknown")
    desk, rail = _two_step(state_store, now=now, hold_error=error)
    _quote(desk)
    now[0] = NOW + 601
    desk.reconcile()
    assert rail.released_ids == [HELD if held else None]


def _at_bank(name, **change):
    """A recorded sandbox answer, as the bank holds it for this desk's hold."""
    body = recorded(name)["body"]
    bound = {
        "account_id": "account_payer",
        "destination_account_id": "account_payee",
        "amount": 20000,
        "idempotency_key": KEY,
    }
    return 200, {**body, **bound, **change}


def _sent(cassette):
    return [
        (r.method, r.url.path, r.headers.get("idempotency-key"))
        for r in cassette.requests
    ]


def _on_the_sandbox(store, *answers):
    cassette = Cassette("balance_lookup", *answers)
    rail = IncreaseRail(cassette.client(), ACCOUNTS, two_step=True)
    desk = _desk(store, bank=rail)
    desk.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))
    return desk, cassette


SANDBOX_HELD = recorded("account_transfer_pending")["body"]["id"]


def test_a_desk_on_the_sandbox_holds_at_quote_and_approves_at_confirm(state_store):
    desk, cassette = _on_the_sandbox(
        state_store,
        _at_bank("account_transfer_pending"),
        _at_bank("account_transfer_approved"),
    )
    q = _quote(desk)
    done = _approve_and_confirm(desk, q)
    assert (done["status"], done["payment_id"]) == ("confirmed", SANDBOX_HELD)
    assert _sent(cassette) == [
        ("GET", "/accounts/account_payer/balance", None),
        ("POST", "/account_transfers", KEY),
        (
            "POST",
            f"/account_transfers/{SANDBOX_HELD}/approve",
            f"mandate-approve-{SANDBOX_HELD}",
        ),
    ]
    assert json.loads(cassette.requests[1].content)["require_approval"] is True
    assert _holds(state_store) == {}
    assert desk.confirm(q["quote_id"]) == done
    assert len(cassette.requests) == 3


def test_a_restarted_sandbox_desk_cancels_the_hold_by_its_id(state_store):
    desk, _ = _on_the_sandbox(state_store, _at_bank("account_transfer_pending"))
    _quote(desk)
    cassette = Cassette(
        _at_bank("account_transfer_pending"),
        _at_bank("account_transfer_canceled", id=SANDBOX_HELD),
        (200, {"data": [], "next_cursor": None}),
    )
    rail = IncreaseRail(cassette.client(), ACCOUNTS, two_step=True)
    again, store = _restart(state_store, bank=rail)
    report = again.reconcile()
    assert report.resolved == ("q:000001 -> hold canceled",)
    assert _sent(cassette)[:2] == [
        ("GET", f"/account_transfers/{SANDBOX_HELD}", None),
        (
            "POST",
            f"/account_transfers/{SANDBOX_HELD}/cancel",
            f"mandate-cancel-{SANDBOX_HELD}",
        ),
    ]
    assert store.records("hold") == []
    store.close()
