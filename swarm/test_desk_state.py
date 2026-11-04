import base64
import itertools
import json
import sqlite3

import pytest

from bank.api import Bank, PaymentRequest, RailError, ReplayError
from bank.conftest import RecordingRail
from bank.verifier import Verifier
from gate.certs import public_key_of, read_claims
from gate.consent import Consent, sign_approval
from gate.state import StateStore
from swarm.conftest import DEMO_INTENT
from swarm.desk import (
    PaymentDesk,
    _Intent,
    _intent_from,
    _intent_record,
    _Unsettled,
)
from swarm.intent import sign_intent
from swarm.test_receipt import GATE, GOLDEN, HOLDER, _pay

NOW = 1800001000


def _desk(store, nonce_from=1, bank=None, now=None, publish=None):
    nonces = itertools.count(nonce_from)
    action_salts = itertools.count(nonce_from)
    salts = itertools.count(nonce_from)
    clock = now or [NOW]
    desk = PaymentDesk(
        source="checking-881",
        bank=bank or Bank({"checking-881": 50000, "acme-991": 0}, state=store),
        verifier=Verifier(public_key_of(GATE), state=store),
        gate_key=GATE,
        clock=lambda: clock[0],
        nonces=lambda: f"{next(nonces):032x}",
        publish=publish,
        action_salts=lambda: bytes([next(action_salts) % 256]) * 32,
        salts=lambda: bytes([next(salts) % 256]) * 16,
        state=store,
    )
    desk.register_holder(public_key_of(HOLDER))
    return desk


def _restart(store, nonce_from=101, bank=None):
    path = store.path
    store.close()
    again = StateStore(path)
    return _desk(again, nonce_from, bank), again


def test_a_desk_with_a_store_issues_the_golden_receipt(state_store, sign_quote):
    desk = _desk(state_store)
    done = _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    receipt = desk.proof_receipt(done["payment_id"])
    assert json.dumps(receipt, separators=(",", ":")) + "\n" == GOLDEN.read_text()


def test_a_restarted_desk_serves_the_same_receipt_and_seal(state_store, sign_quote):
    desk = _desk(state_store)
    done = _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    receipt, seal, root = (
        desk.proof_receipt(done["payment_id"]),
        desk.latest_seal(),
        desk.registry.root(),
    )
    again, _ = _restart(state_store)
    assert again.proof_receipt(done["payment_id"]) == receipt
    assert (again.latest_seal(), again.registry.root()) == (seal, root)
    assert again.receipt(done["payment_id"])["status"] == "confirmed"
    assert again.status("q:000001")["status"] == "confirmed"


def test_a_restarted_desk_numbers_quotes_and_payments_on(state_store, sign_quote):
    _pay(_desk(state_store), sign_quote, "acme-991", 20000, "A-991")
    again, _ = _restart(state_store)
    done = _pay(again, sign_quote, "acme-991", 300, "A-993")
    assert (done["quote_id"], done["payment_id"]) == ("q:000002", "pay:000002")
    claims, _ = read_claims(
        again.proof_receipt("pay:000002")["certificate"], public_key_of(GATE)
    )
    assert claims["revocation_index"] == 2
    assert again.bank.get_balance("acme-991") == 20300


def test_a_restarted_desk_keeps_its_holder(state_store):
    _desk(state_store)
    again, _ = _restart(state_store)
    assert again.holder_keys == (public_key_of(HOLDER),)
    assert again.register_holder(b"\x07" * 32) is False


def test_an_intent_pays_once_across_a_restart(state_store):
    desk = _desk(state_store)
    desk.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    _approve_and_confirm(desk, q)
    paid = desk.intent_receipt("i:000001")
    again, _ = _restart(state_store)
    assert again.intent_receipt("i:000001") == paid
    assert (
        again.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))["reason"]
        == "intent: already recorded"
    )
    q2 = again.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    assert _approve_and_confirm(again, q2)["reason"] == "intent: already used"


def _approve_and_confirm(desk, q):
    desk.approve(
        q["quote_id"], sign_approval(HOLDER, Consent(**q["consent"], signature=b""))
    )
    return desk.confirm(q["quote_id"])


class _Watching(RecordingRail):
    """A rail that records which journal entries existed when it was called."""

    def __init__(self, store, **kwargs):
        super().__init__(**kwargs)
        self.store = store
        self.seen = []

    def execute(self, request, action_hash, idempotency_key=None):
        self.seen.append([k for k, _ in self.store.records("pending")])
        return super().execute(request, action_hash, idempotency_key)


def _sandbox(store, now=None, publish=None, **rail):
    watching = _Watching(store, balance=50000, **rail)
    desk = _desk(store, bank=watching, now=now, publish=publish)
    desk.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    return desk, watching, q


def test_the_certificate_is_journaled_before_the_bank_is_called(state_store):
    desk, rail, q = _sandbox(state_store)
    assert _approve_and_confirm(desk, q)["status"] == "confirmed"
    assert rail.seen == [["q:000001"]]
    assert state_store.records("pending") == []


@pytest.mark.parametrize(
    ("error", "kept"),
    [
        (RailError("bank: refused"), False),
        (RailError("bank: outcome unknown"), True),
    ],
)
def test_only_an_unknown_outcome_stays_journaled(state_store, error, kept):
    desk, _, q = _sandbox(state_store, error=error)
    assert _approve_and_confirm(desk, q)["reason"] == str(error)
    pending = state_store.records("pending")
    assert bool(pending) is kept
    if kept:
        journal = json.loads(pending[0][1])
        assert journal["idempotency_key"] == (
            "mandate-cert-00000000000000000000000000000002"
        )
        assert journal["expires_at"] == NOW + 300
        assert base64.b64decode(journal["holder_key"]) == public_key_of(HOLDER)
        assert journal["action_salt"] == "01" * 32


def test_the_simulated_ledger_survives_a_restart(tmp_path):
    path = tmp_path / "state.db"
    bank = Bank({"checking-881": 50000, "acme-991": 0}, state=StateStore(path))
    request = PaymentRequest("checking-881", "acme-991", 20000, "USD", "A-991")
    bank.execute(request, "h1", "mandate-cert-k1")
    again = Bank({"checking-881": 1, "acme-991": 1}, state=StateStore(path))
    assert (again.get_balance("checking-881"), again.get_balance("acme-991")) == (
        30000,
        20000,
    )
    with pytest.raises(ReplayError):
        again.execute(request, "h1", "mandate-cert-k1")
    assert again.execute(request, "h2", "mandate-cert-k2").payment_id == "pay:000002"


class _Crash(BaseException):
    """The process dies here: nothing after this line runs."""


def test_a_crash_during_the_bank_call_leaves_the_intent_unsettled(state_store):
    desk, rail, q = _sandbox(state_store, error=_Crash())
    with pytest.raises(_Crash):
        _approve_and_confirm(desk, q)
    again, store = _restart(state_store, bank=rail)
    assert [k for k, _ in store.records("pending")] == ["q:000001"]
    assert again.status("q:000001")["reason"] == "bank: outcome unknown"
    view = again.intent_receipt("i:000001")
    assert view["status"] == "unsettled"
    assert view["idempotency_key"] == "mandate-cert-00000000000000000000000000000002"
    q2 = again.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    assert _approve_and_confirm(again, q2)["reason"] == "intent: unsettled"
    assert len(rail.calls) == 1


def test_an_unsettled_intent_is_settled_after_a_restart(state_store):
    desk, rail, q = _sandbox(state_store, error=RailError("bank: outcome unknown"))
    _approve_and_confirm(desk, q)
    again, store = _restart(state_store, bank=rail)
    assert again.intent_receipt("i:000001")["status"] == "unsettled"
    rail.found = True
    assert again.reconcile("i:000001")["status"] == "paid"
    assert store.records("pending") == []
    third, _ = _restart(store, bank=rail)
    assert third.intent_receipt("i:000001")["payment_id"] == "account_transfer_t1"
    assert third.status("q:000001")["reason"] == "ok: reconciled"
    assert third.receipt("account_transfer_t1")["status"] == "confirmed"


def test_a_failed_commit_keeps_the_journal_and_the_registry_true(
    state_store, monkeypatch
):
    desk, rail, q = _sandbox(state_store)
    put = state_store.put_record

    def failing(kind, key, value):
        if kind == "receipt":
            raise sqlite3.OperationalError("disk I/O error")
        put(kind, key, value)

    monkeypatch.setattr(state_store, "put_record", failing)
    with pytest.raises(sqlite3.OperationalError):
        _approve_and_confirm(desk, q)
    assert desk.registry.size() == len(state_store.entries()) == 0
    assert desk.latest_seal() is None
    assert [k for k, _ in state_store.records("pending")] == ["q:000001"]
    assert desk.status("q:000001")["reason"] == "bank: outcome unknown"
    assert desk.intent_receipt("i:000001")["status"] == "unsettled"
    assert desk.confirm("q:000001")["reason"] == "bank: outcome unknown"
    assert len(rail.calls) == 1


def test_a_confirm_prunes_expired_fences(state_store, sign_quote):
    state_store.consume("jti", "old", NOW - 1)
    _pay(_desk(state_store), sign_quote, "acme-991", 20000, "A-991")
    assert not state_store.used("jti", "old")
    assert state_store.used("jti", "00000000000000000000000000000002")


def test_an_intent_record_keeps_every_field():
    request = PaymentRequest("checking-881", "acme-991", 20000, "USD", "A-991")
    unsettled = _Unsettled("q:000001", request, "ab" * 32, "k", "r", NOW)
    funds = {"kind": "zktls", "evidence_ref": "ev:z", "session_time": NOW}
    intent = _Intent(DEMO_INTENT, "h", "ev:f", "ev:i", "pay:1", unsettled, funds)
    record = json.loads(json.dumps(_intent_record(intent)))
    assert _intent_from(record) == intent


def test_a_refused_payment_spends_no_key_on_disk(tmp_path):
    path = tmp_path / "state.db"
    bank = Bank({"checking-881": 100, "acme-991": 0}, state=StateStore(path))
    request = PaymentRequest("checking-881", "acme-991", 20000, "USD", "A-991")
    with pytest.raises(ValueError, match="insufficient funds"):
        bank.execute(request, "h1", "mandate-cert-k1")
    again = Bank({}, state=StateStore(path))
    assert again.get_balance("checking-881") == 100
    assert again.reconcile(request, "h1", "mandate-cert-k1") is None


@pytest.mark.parametrize(
    "reason", ["bank: outcome unknown", "bank: not complete", "bank: transfer differs"]
)
def test_every_unsettled_reason_stays_journaled(state_store, reason):
    desk, _, q = _sandbox(state_store, error=RailError(reason))
    assert _approve_and_confirm(desk, q)["reason"] == reason
    assert [k for k, _ in state_store.records("pending")] == ["q:000001"]
    again, _ = _restart(state_store)
    assert again.intent_receipt("i:000001")["status"] == "unsettled"
