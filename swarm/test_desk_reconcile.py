import json
import sqlite3
import threading

import httpx
import pytest

from bank.api import RailError
from bank.conftest import SENTINEL_KEY, RecordingRail, ach_body
from bank.increase import IncreaseRail, sandbox_client
from bank.reconcile import BankTransfer
from bank.test_increase import ACCOUNTS
from gate.state import StateStore
from swarm.conftest import DEMO_INTENT
from swarm.intent import sign_intent
from swarm.test_desk_state import (
    HOLDER,
    NOW,
    _approve_and_confirm,
    _desk,
    _sandbox,
    _Watching,
)

KEY = "mandate-cert-00000000000000000000000000000002"


def _unknown(store, now=None, publish=None):
    desk, rail, q = _sandbox(
        store, now=now, publish=publish, error=RailError("bank: outcome unknown")
    )
    assert _approve_and_confirm(desk, q)["reason"] == "bank: outcome unknown"
    rail.error = None
    return desk, rail


def _done(transfer_id="account_transfer_t1", key=KEY, status="complete"):
    return BankTransfer(transfer_id, 20000, status, key, "2027-01-15T08:20:00Z")


def test_an_unknown_outcome_the_bank_completed_becomes_a_sealed_payment(
    state_store,
):
    lines = []
    desk, rail = _unknown(state_store, publish=lines.append)
    rail.listed = [_done()]
    report = desk.reconcile()
    assert (report.resolved, report.pending, report.unbacked) == (
        ("q:000001 -> account_transfer_t1",),
        (),
        (),
    )
    assert (report.transfers, report.certified) == (1, 1)
    receipt = desk.proof_receipt("account_transfer_t1")
    entry = json.loads(receipt["registry"]["entry"]["body"])
    assert (entry["reason"], entry["status"]) == ("ok: executed", "confirmed")
    assert desk.latest_seal()["seq_to"] == desk.registry.size() == 2
    assert desk.status("q:000001")["payment_id"] == "account_transfer_t1"
    assert lines[-1].subject["reason"] == "ok: reconciled at the bank"
    assert state_store.records("pending") == []


def test_an_unknown_outcome_waits_while_its_certificate_lives(state_store):
    desk, rail = _unknown(state_store)
    report = desk.reconcile()
    assert (report.resolved, report.pending) == ((), ("q:000001",))
    assert desk.registry.size() == 1


def test_a_transfer_still_awaiting_approval_stays_pending(state_store):
    desk, rail = _unknown(state_store)
    rail.listed = [_done(status="pending_approval")]
    report = desk.reconcile()
    assert (report.resolved, report.pending) == ((), ("q:000001",))
    assert desk.registry.size() == 1
    assert state_store.records("receipt") == []


# The certificate expires 300 s after the attempt; the settle margin is 60 s.
RELEASE = NOW + 300 + 60


@pytest.mark.parametrize("later", [NOW + 301, RELEASE - 1])
def test_an_absent_transfer_stays_pending_until_expiry_and_the_margin(
    state_store, later
):
    now = [NOW]
    desk, _ = _unknown(state_store, now=now)
    now[0] = later
    report = desk.reconcile()
    assert (report.resolved, report.pending) == ((), ("q:000001",))
    assert desk.intent_receipt("i:000001")["status"] == "unsettled"


def test_an_unknown_outcome_the_bank_never_saw_is_sealed_as_not_paid(state_store):
    now = [NOW]
    desk, _ = _unknown(state_store, now=now)
    now[0] = RELEASE
    report = desk.reconcile()
    assert report.resolved == ("q:000001 -> not paid",)
    last = desk.registry.entry(desk.registry.size())
    assert json.loads(last.body)["reason"] == "bank: no transfer under this certificate"
    assert desk.latest_seal()["seq_to"] == 2


def test_a_crash_during_the_bank_call_is_settled_after_restart(state_store):
    _unknown(state_store)
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    rail = _Watching(store, balance=50000)
    rail.listed = [_done()]
    again = _desk(store, nonce_from=101, bank=rail)
    report = again.reconcile()
    assert report.resolved == ("q:000001 -> account_transfer_t1",)
    receipt = again.proof_receipt("account_transfer_t1")
    proof = receipt["registry"]["proof"]
    assert proof["root"] == again.latest_seal()["root"]
    assert rail.calls == [] and store.records("pending") == []
    store.close()


def test_an_unreachable_bank_reports_unavailable_and_changes_nothing(state_store):
    desk, rail = _unknown(state_store)
    rail.listed_error = RailError("bank: unavailable")
    size = desk.registry.size()
    report = desk.reconcile()
    assert (report.error, report.transfers, report.pending) == (
        "bank: unavailable",
        0,
        ("q:000001",),
    )
    assert desk.registry.size() == size
    assert json.loads(state_store.get("reconciliation"))["error"] == "bank: unavailable"


def test_reconcile_never_moves_money(state_store):
    desk, rail, q = _sandbox(state_store)
    _approve_and_confirm(desk, q)
    rail.listed = [_done(), _done("account_transfer_x", "payroll")]
    before = list(rail.calls)
    report = desk.reconcile()
    assert (report.certified, report.unbacked) == (1, ("account_transfer_x",))
    assert rail.calls == before


def test_a_found_transfer_of_another_amount_stays_pending(state_store):
    desk, rail = _unknown(state_store)
    rail.listed = [BankTransfer("account_transfer_t1", 19999, "complete", KEY, "")]
    report = desk.reconcile()
    assert (report.resolved, report.pending) == ((), ("q:000001",))
    assert desk.proof_receipt("account_transfer_t1") is None
    assert report.unbacked == ("account_transfer_t1",)


def test_a_found_transfer_the_bank_says_differs_stays_pending(state_store):
    desk, rail = _unknown(state_store)
    rail.listed = [_done()]
    rail.found = RailError("bank: transfer differs")
    report = desk.reconcile()
    assert (report.resolved, report.pending, report.error) == ((), ("q:000001",), None)
    assert desk.registry.size() == 1


def test_a_settled_journal_is_never_settled_twice(state_store):
    desk, rail = _unknown(state_store)
    rail.listed = [_done()]
    desk.reconcile()
    again = desk.reconcile()
    assert (again.resolved, again.pending, again.certified) == ((), (), 1)
    assert desk.registry.size() == 2


@pytest.mark.parametrize("later", [NOW + 61, NOW + 301, RELEASE - 1])
def test_a_lookup_finding_nothing_keeps_a_journaled_intent_until_release(
    state_store, later
):
    now = [NOW]
    desk, _ = _unknown(state_store, now=now)
    now[0] = later
    assert desk.reconcile_intent("i:000001")["status"] == "unsettled"
    assert state_store.record("pending", "q:000001") is not None
    assert desk.registry.size() == 1


def test_a_lookup_finding_nothing_after_release_seals_not_paid(state_store):
    now = [NOW]
    desk, _ = _unknown(state_store, now=now)
    now[0] = RELEASE
    assert desk.reconcile_intent("i:000001")["status"] == "signed"
    last = desk.registry.entry(desk.registry.size())
    assert json.loads(last.body)["reason"] == "bank: no transfer under this certificate"
    assert state_store.records("pending") == []
    assert (
        desk.status("q:000001")["reason"] == "bank: no transfer under this certificate"
    )


def _paid_again(state_store, now):
    desk, rail = _unknown(state_store, now=now)
    now[0] = RELEASE
    assert desk.reconcile_intent("i:000001")["status"] == "signed"
    rail.paid_id = "account_transfer_t2"
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    assert _approve_and_confirm(desk, q)["payment_id"] == "account_transfer_t2"
    return desk, rail


def test_a_late_transfer_for_a_released_intent_that_paid_again_is_paid_twice(
    state_store,
):
    now = [NOW]
    desk, rail = _paid_again(state_store, now)
    late = BankTransfer("account_transfer_t1", 20000, "complete", KEY, "")
    rail.listed = [late, _done("account_transfer_t2", rail.calls[-1][2])]
    report = desk.reconcile()
    assert report.paid_twice == (
        "i:000001 -> account_transfer_t2 + account_transfer_t1",
    )
    assert report.view()["paid_twice"] == list(report.paid_twice)
    assert report.unbacked == ("account_transfer_t1",)
    assert desk.intent_receipt("i:000001")["payment_id"] == "account_transfer_t2"
    assert desk.latest_reconciliation()["paid_twice"] == list(report.paid_twice)


def test_a_double_payment_is_reported_after_a_restart(state_store):
    now = [NOW]
    desk, rail = _paid_again(state_store, now)
    rail.listed = [BankTransfer("account_transfer_t1", 20000, "complete", KEY, "")]
    desk.reconcile()
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    again = _desk(store, nonce_from=101, bank=rail, now=now)
    assert again.reconcile().paid_twice == (
        "i:000001 -> account_transfer_t2 + account_transfer_t1",
    )
    store.close()


def test_an_intent_settled_by_its_own_lookup_is_certified(state_store):
    desk, rail = _unknown(state_store)
    rail.listed = [_done()]
    assert desk.reconcile_intent("i:000001")["status"] == "paid"
    assert desk.proof_receipt("account_transfer_t1") is not None
    report = desk.reconcile()
    assert (report.certified, report.unbacked, report.resolved) == (1, (), ())
    assert desk.latest_reconciliation() == report.view()


class _Blind(RecordingRail):
    """A rail that moves money but cannot list what it holds."""

    transfers = None  # type: ignore[assignment]


def test_reconcile_needs_a_rail_that_lists(state_store):
    desk = _desk(state_store, bank=_Blind())
    with pytest.raises(ValueError, match="the rail cannot list transfers"):
        desk.reconcile()


def test_a_journal_row_that_does_not_parse_is_reported_and_the_rest_runs(
    state_store,
):
    desk, rail = _unknown(state_store)
    state_store.put_record("pending", "q:000001", "{not json")
    rail.listed = [_done()]
    report = desk.reconcile()
    assert (report.unreadable, report.error, report.transfers) == (
        ("pending q:000001",),
        None,
        1,
    )
    assert report.unbacked == ("account_transfer_t1",)
    assert desk.registry.size() == 1


def test_a_journal_row_missing_fields_is_reported(state_store):
    desk, rail = _unknown(state_store)
    state_store.put_record("pending", "q:000001", json.dumps({"quote_id": "q:000001"}))
    report = desk.reconcile()
    assert (report.unreadable, report.pending, report.error) == (
        ("pending q:000001",),
        (),
        None,
    )


def test_a_receipt_row_that_does_not_parse_is_reported(state_store):
    desk, rail, q = _sandbox(state_store)
    _approve_and_confirm(desk, q)
    path = state_store.path
    raw = sqlite3.connect(path)
    raw.execute(
        "UPDATE records SET value = ? WHERE kind = 'receipt'",
        (json.dumps({"payment_id": "account_transfer_t1"}),),
    )
    raw.commit()
    raw.close()
    state_store.close()
    store = StateStore(path)
    again = _desk(store, nonce_from=101, bank=rail)
    rail.listed = [_done()]
    report = again.reconcile()
    assert (report.unreadable, report.unbacked, report.error) == (
        ("receipt account_transfer_t1",),
        ("account_transfer_t1",),
        None,
    )
    store.close()


def test_a_restart_with_a_journal_that_does_not_parse_is_refused(state_store):
    _unknown(state_store)
    state_store.put_record("pending", "q:000001", json.dumps({"intent_id": 7}))
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    with pytest.raises(ValueError, match="^state: store unreadable$"):
        _desk(store, nonce_from=101, bank=RecordingRail(balance=50000))
    store.close()


@pytest.mark.parametrize("raised", [AttributeError("data"), TypeError("x")])
def test_a_listing_that_fails_oddly_is_unavailable(state_store, raised):
    desk, rail, q = _sandbox(state_store)
    _approve_and_confirm(desk, q)
    rail.listed_error = raised
    report = desk.reconcile()
    assert (report.error, report.transfers) == ("bank: unavailable", 0)


def test_a_lookup_that_fails_oddly_keeps_the_journal_pending(state_store):
    desk, rail = _unknown(state_store)
    rail.listed_error = AttributeError("data")
    report = desk.reconcile()
    assert (report.error, report.pending) == ("bank: unavailable", ("q:000001",))


def test_a_round_that_fails_records_the_failure_and_its_time(state_store):
    now = [NOW]
    desk, rail = _unknown(state_store, now=now)
    desk.reconcile()
    now[0] = NOW + 90

    def broken(kind):
        raise RuntimeError("boom")

    state_store.records = broken
    with pytest.raises(RuntimeError):
        desk.reconcile()
    latest = desk.latest_reconciliation()
    assert (latest["error"], latest["checked_at"]) == ("reconcile: failed", NOW + 90)


class _Slow(RecordingRail):
    """A rail whose listing and lookups ask the desk for a view meanwhile."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.desk = None
        self.answered = []

    def _ask(self):
        done = threading.Event()

        def ask():
            self.desk.pending()
            done.set()

        threading.Thread(target=ask, daemon=True).start()
        self.answered.append(done.wait(2))

    def transfers(self, from_acct, since):
        self._ask()
        return super().transfers(from_acct, since)

    def transfer_by_key(self, key):
        self._ask()
        return super().transfer_by_key(key)


def test_the_desk_answers_while_the_bank_is_asked(state_store):
    rail = _Slow(balance=50000)
    desk = _desk(state_store, bank=rail)
    rail.desk = desk
    desk.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    rail.error = RailError("bank: outcome unknown")
    _approve_and_confirm(desk, q)
    rail.error = None
    desk.reconcile()
    assert rail.answered == [True, True]


class _Racing(RecordingRail):
    """A rail whose lookup lets the intent's own lookup settle it first."""

    desk = None

    def transfer_by_key(self, key):
        found = super().transfer_by_key(key)
        racer = threading.Thread(target=self.desk.reconcile_intent, args=("i:000001",))
        racer.start()
        racer.join(2)
        return found


def test_a_journal_settled_meanwhile_is_not_settled_again(state_store):
    rail = _Racing(balance=50000)
    desk = _desk(state_store, bank=rail)
    rail.desk = desk
    desk.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    rail.error = RailError("bank: outcome unknown")
    _approve_and_confirm(desk, q)
    rail.error = None
    rail.listed = [_done()]
    report = desk.reconcile()
    assert (report.resolved, report.pending, report.certified) == ((), (), 1)
    assert desk.registry.size() == 2


def test_a_journal_records_its_rail(state_store):
    _unknown(state_store)
    [(_, value)] = state_store.records("pending")
    assert json.loads(value)["rail"] == "sandbox"


def test_a_journal_from_another_rail_is_never_settled_here(state_store):
    now = [NOW]
    desk, rail = _unknown(state_store, now=now)
    [(quote_id, value)] = state_store.records("pending")
    state_store.put_record(
        "pending", quote_id, json.dumps({**json.loads(value), "rail": "simulated"})
    )
    now[0] = RELEASE
    report = desk.reconcile()
    assert (report.resolved, report.pending) == ((), ("q:000001",))
    assert desk.reconcile_intent("i:000001")["status"] == "unsettled"
    assert desk.registry.size() == 1


class _AchAtTheBank:
    """A sandbox that holds one ACH transfer under the journal's key."""

    def __init__(self, status):
        self.ach = ach_body(idempotency_key=KEY, status=status)
        self.asked = []

    def __call__(self, request):
        self.asked.append((request.method, request.url.path, dict(request.url.params)))
        if (request.method, request.url.path) == ("GET", "/account_transfers"):
            return httpx.Response(200, json={"data": [], "next_cursor": None})
        if (request.method, request.url.path) == ("GET", "/ach_transfers"):
            return httpx.Response(200, json={"data": [self.ach], "next_cursor": None})
        return httpx.Response(500, json={"type": "unexpected"})


@pytest.mark.parametrize("status", ["pending_submission", "submitted"])
def test_an_ach_journal_is_never_freed_by_a_restart_without_ach(state_store, status):
    now = [NOW]
    _unknown(state_store, now=now)
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    bank = _AchAtTheBank(status)
    client = sandbox_client(
        SENTINEL_KEY, httpx.Client(transport=httpx.MockTransport(bank))
    )
    rail = IncreaseRail(client, ACCOUNTS)
    now[0] = RELEASE + 3600
    again = _desk(store, nonce_from=101, bank=rail, now=now)
    report = again.reconcile()
    assert (report.resolved, report.pending) == ((), ("q:000001",))
    assert report.unbacked == (bank.ach["id"],)
    assert again.intent_receipt("i:000001")["status"] == "unsettled"
    assert len(store.records("pending")) == 1
    assert ("GET", "/ach_transfers", {"idempotency_key": KEY}) in bank.asked
    assert [
        a for a in bank.asked if a[1] not in ("/account_transfers", "/ach_transfers")
    ] == []
    store.close()
