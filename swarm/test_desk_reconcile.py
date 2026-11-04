import json

import pytest

from bank.api import RailError
from bank.conftest import RecordingRail
from bank.reconcile import BankTransfer
from gate.state import StateStore
from swarm.test_desk_state import (
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


def test_an_unknown_outcome_the_bank_never_saw_is_sealed_as_not_paid(state_store):
    now = [NOW]
    desk, _ = _unknown(state_store, now=now)
    now[0] = NOW + 301
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


def test_a_transfer_found_after_the_intent_was_released_is_sealed(state_store):
    now = [NOW]
    desk, rail = _unknown(state_store, now=now)
    now[0] = NOW + 61
    assert desk.reconcile("i:000001")["status"] == "signed"
    rail.listed = [_done()]
    report = desk.reconcile()
    assert report.resolved == ("q:000001 -> account_transfer_t1",)
    assert desk.intent_receipt("i:000001")["payment_id"] == "account_transfer_t1"


def test_an_intent_settled_by_its_own_lookup_is_certified(state_store):
    desk, rail = _unknown(state_store)
    rail.listed = [_done()]
    assert desk.reconcile("i:000001")["status"] == "paid"
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
