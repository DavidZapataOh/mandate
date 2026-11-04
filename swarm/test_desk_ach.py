import base64
import json

import httpx
import pytest

from bank.api import RailError
from bank.conftest import SENTINEL_KEY, RecordingRail
from bank.increase import IncreaseRail, sandbox_client
from bank.reconcile import AchState, BankTransfer
from bank.test_increase import ACCOUNTS
from gate.certs import public_key_of
from gate.registry import Anchor, InclusionProof, verify_anchor, verify_inclusion
from gate.state import StateStore
from swarm.conftest import DEMO_INTENT
from swarm.desk import ACH_WATCH_S
from swarm.hub import EventHub
from swarm.intent import sign_intent
from swarm.server import build_server
from swarm.test_desk_reconcile import RELEASE, _AchAtTheBank
from swarm.test_desk_state import HOLDER, NOW, _approve_and_confirm, _desk, _restart
from swarm.test_receipt import GATE
from swarm.test_server import FOREIGN, PAIR, _asgi

PID = "ach_transfer_t1"
KEY = "mandate-cert-00000000000000000000000000000002"
SUMMARY = "Pay 200.00 USD to acme-991 (ref A-991) from checking-881"
SETTLED_AT = "2027-01-15T09:16:40Z"
RETURNED_AT = "2027-01-16T08:16:40Z"
IN_FLIGHT = AchState(PID, "pending_submission", None, None, None, None)
SETTLED = AchState(PID, "submitted", SETTLED_AT, None, None, None)
RETURNED = AchState(
    PID, "returned", SETTLED_AT, "R01", "insufficient_fund", RETURNED_AT
)
SETTLEMENT_BODY = (
    '{"execution_seq":1,"payment_id":"ach_transfer_t1","quote_id":"q:000001",'
    '"settled_at":"2027-01-15T09:16:40Z","status":"settled"}'
)
RETURN_BODY = (
    '{"code":"R01","execution_seq":1,"label":"SIMULATED RETURN",'
    '"payment_id":"ach_transfer_t1","quote_id":"q:000001",'
    '"reason":"insufficient_fund","returned_at":"2027-01-16T08:16:40Z",'
    '"status":"returned"}'
)


def _paid(store, now=None, rail=None):
    rail = rail or RecordingRail(balance=50000, ach=True)
    lines = []
    desk = _desk(store, bank=rail, now=now, publish=lines.append)
    desk.record_intent(DEMO_INTENT, sign_intent(HOLDER, DEMO_INTENT))
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    return desk, rail, lines, _approve_and_confirm(desk, q)


def _bodies(store, kind):
    return [e.body for e in store.entries() if e.kind == kind]


def _settles(lines):
    return [x.subject for x in lines if x.subject.get("step") == "settle"]


def _record(store):
    return {k: json.loads(v) for k, v in store.records("ach")}


def test_an_accepted_ach_payment_is_paid_and_tracked(state_store):
    desk, rail, _, done = _paid(state_store)
    assert (done["status"], done["payment_id"]) == ("confirmed", PID)
    receipt = desk.proof_receipt(PID)
    assert receipt is not None
    assert _record(state_store) == {
        PID: {
            "quote_id": "q:000001",
            "intent_id": "i:000001",
            "idempotency_key": KEY,
            "execution_seq": 1,
            "summary": SUMMARY,
            "state": "in_flight",
            "since": NOW,
            "entries": [],
        }
    }
    assert desk.intent_receipt("i:000001")["status"] == "paid"
    assert desk.lifecycle(PID)["events"] == []


def test_settlement_is_sealed_once_and_linked_to_the_payment(state_store):
    desk, rail, lines, _ = _paid(state_store)
    rail.states[PID] = SETTLED
    assert desk.track_ach(PID) == "settled"
    assert desk.track_ach(PID) is None
    assert _bodies(state_store, "settlement") == [SETTLEMENT_BODY]
    assert _settles(lines) == [
        {
            "step": "settle",
            "quote_id": "q:000001",
            "status": "settled",
            "summary": SUMMARY,
            "payment_id": PID,
            "reason": "ok: settled at the bank",
        }
    ]
    assert _record(state_store)[PID]["entries"] == [2]


def test_a_return_appends_linked_entries_and_the_intent_pays_nothing_more(
    state_store,
):
    desk, rail, lines, _ = _paid(state_store)
    rail.states[PID] = RETURNED
    assert desk.track_ach(PID) == "returned"
    assert _bodies(state_store, "settlement") == [SETTLEMENT_BODY]
    assert _bodies(state_store, "return") == [RETURN_BODY]
    assert [s["reason"] for s in _settles(lines)] == [
        "ok: settled at the bank",
        "bank: returned R01 insufficient_fund (SIMULATED RETURN)",
    ]
    view = desk.intent_receipt("i:000001")
    assert (view["status"], view["payment_id"]) == ("returned", PID)
    assert view["detail"] == (
        "The bank returned payment ach_transfer_t1 (R01 insufficient_fund, "
        "SIMULATED RETURN); the money went back to the paying account. This "
        "intent pays nothing more: sign a new intent to pay again."
    )
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    assert _approve_and_confirm(desk, q)["reason"] == "intent: already used"
    assert len(rail.calls) == 1


def test_a_return_survives_a_restart_and_is_sealed_once(state_store):
    _, rail, _, _ = _paid(state_store)
    again, store = _restart(state_store, bank=rail)
    rail.states[PID] = RETURNED
    rail.listed = [BankTransfer(PID, 20000, "returned", KEY, "")]
    report = again.reconcile()
    assert report.resolved == (
        "ach_transfer_t1 -> settled",
        "ach_transfer_t1 -> returned R01 (SIMULATED RETURN)",
    )
    assert (report.transfers, report.certified) == (0, 0)
    assert (report.unbacked, report.missing, report.error) == ((), (), None)
    assert again.reconcile().resolved == ()
    assert len(_bodies(store, "return")) == 1
    third, store = _restart(store, bank=rail)
    assert third.intent_receipt("i:000001")["status"] == "returned"
    assert third.lifecycle(PID)["label"] == "SIMULATED RETURN"
    store.close()


def test_a_lost_ach_answer_is_sealed_and_tracked_by_the_reconciler(state_store):
    rail = RecordingRail(RailError("bank: outcome unknown"), balance=50000, ach=True)
    desk, rail, _, done = _paid(state_store, rail=rail)
    assert done["reason"] == "bank: outcome unknown"
    rail.error = None
    rail.listed = [BankTransfer(PID, 20000, "pending_submission", KEY, "")]
    rail.states[PID] = IN_FLIGHT
    report = desk.reconcile()
    assert report.resolved == ("q:000001 -> ach_transfer_t1",)
    assert (report.transfers, report.certified, report.unbacked) == (1, 1, ())
    assert _record(state_store)[PID]["state"] == "in_flight"


def test_an_unreadable_bank_keeps_the_payment_in_flight(state_store):
    desk, rail, _, _ = _paid(state_store)
    rail.states[PID] = RailError("bank: unavailable")
    report = desk.reconcile()
    assert (report.error, report.resolved) == ("bank: unavailable", ())
    assert _record(state_store)[PID]["state"] == "in_flight"
    assert _bodies(state_store, "return") == []


@pytest.mark.parametrize(
    ("later", "read"), [(NOW + ACH_WATCH_S - 1, True), (NOW + ACH_WATCH_S, False)]
)
def test_a_settled_payment_is_watched_for_returns_for_five_days(
    state_store, later, read
):
    now = [NOW]
    desk, rail, _, _ = _paid(state_store, now=now)
    rail.states[PID] = SETTLED
    desk.track_ach(PID)
    now[0] = later
    desk.reconcile()
    assert rail.state_reads == ([PID, PID] if read else [PID])


def test_an_event_reads_a_payment_past_its_watch(state_store):
    now = [NOW]
    desk, rail, _, _ = _paid(state_store, now=now)
    rail.states[PID] = SETTLED
    desk.track_ach(PID)
    now[0] = NOW + 30 * 86_400
    rail.states[PID] = RETURNED
    assert desk.track_ach(PID) == "returned"


def test_untracked_ids_never_reach_the_bank(state_store):
    desk, rail, _, _ = _paid(state_store)
    assert desk.track_ach("ach_transfer_unknown") is None
    assert desk.lifecycle("ach_transfer_unknown") is None
    assert rail.state_reads == []


def test_an_account_transfer_desk_tracks_nothing(state_store):
    desk, rail, _, done = _paid(state_store, rail=RecordingRail(balance=50000))
    assert desk.lifecycle(done["payment_id"]) is None
    assert state_store.records("ach") == []


def test_a_lifecycle_is_proven_under_the_newest_seal(state_store):
    desk, rail, _, _ = _paid(state_store)
    rail.states[PID] = RETURNED
    desk.track_ach(PID)
    view = desk.lifecycle(PID)
    assert (view["payment_id"], view["label"], view["state"]) == (
        PID,
        "SIMULATED RETURN",
        "returned",
    )
    assert [e["entry"]["kind"] for e in view["events"]] == ["settlement", "return"]
    assert [e["entry"]["body"] for e in view["events"]] == [
        SETTLEMENT_BODY,
        RETURN_BODY,
    ]
    for event in view["events"]:
        p = event["proof"]
        proof = InclusionProof(**{**p, "siblings": tuple(p["siblings"])})
        signature = base64.b64decode(event["seal"]["signature"])
        seal = Anchor(**{**event["seal"], "signature": signature})
        assert proof.seq == event["entry"]["seq"]
        assert verify_inclusion(proof, seal.root)
        assert verify_anchor(seal, public_key_of(GATE))
        assert seal.seq_to == 3


@pytest.mark.anyio
async def test_the_lifecycle_route_serves_the_sealed_events(state_store):
    desk, rail, _, _ = _paid(state_store)
    rail.states[PID] = RETURNED
    desk.track_ach(PID)
    srv = build_server(desk, PAIR, hub=EventHub())
    async with _asgi(srv.streamable_http_app()) as http:
        found = await http.get(f"/api/lifecycle/{PID}")
        missing = await http.get("/api/lifecycle/pay:000009")
    assert (found.status_code, found.json()) == (200, desk.lifecycle(PID))
    assert (missing.status_code, missing.json()) == (404, {"error": "not found"})


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("path", "headers"),
    [(f"/api/lifecycle/{PID}", FOREIGN), (f"/api/lifecycle/{PID}?disclose=all", {})],
)
async def test_the_lifecycle_route_refuses_a_foreign_host_or_a_query(
    state_store, path, headers
):
    desk, rail, _, _ = _paid(state_store)
    rail.states[PID] = RETURNED
    desk.track_ach(PID)
    srv = build_server(desk, PAIR, hub=EventHub())
    async with _asgi(srv.streamable_http_app()) as http:
        refused = await http.get(path, headers=headers)
    assert (refused.status_code, refused.json()) == (400, {"error": "bad request"})


def test_a_returned_ach_is_never_freed_by_a_restart_without_ach(state_store):
    now = [NOW]
    rail = RecordingRail(RailError("bank: outcome unknown"), balance=50000, ach=True)
    _paid(state_store, now=now, rail=rail)
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    bank = _AchAtTheBank("returned")
    client = sandbox_client(
        SENTINEL_KEY, httpx.Client(transport=httpx.MockTransport(bank))
    )
    now[0] = RELEASE + 3600
    again = _desk(store, nonce_from=101, bank=IncreaseRail(client, ACCOUNTS), now=now)
    assert again.reconcile_intent("i:000001")["status"] == "unsettled"
    assert again.reconcile().pending == ("q:000001",)
    assert _bodies(store, "denial") == [
        '{"payment_id":null,"quote_id":"q:000001",'
        '"reason":"bank: outcome unknown","status":"denied"}'
    ]
    assert len(store.records("pending")) == 1
    store.close()


def test_an_ach_desk_needs_a_state_store():
    with pytest.raises(ValueError, match="^ach needs a state store$"):
        _desk(None, bank=RecordingRail(ach=True))


@pytest.mark.parametrize(
    "change",
    [
        {"state": "lost"},
        {"entries": "2"},
        {"execution_seq": 9},
        {"state": "returned"},
        {"entries": [1]},
        {"intent_id": 7},
    ],
)
def test_an_unreadable_ach_record_stops_the_start(state_store, caplog, change):
    _paid(state_store)
    record = _record(state_store)[PID]
    state_store.put_record("ach", PID, json.dumps({**record, **change}))
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    with pytest.raises(ValueError, match="^state: store unreadable$"):
        _desk(store, bank=RecordingRail(ach=True))
    assert f"ach record {PID} does not read" in caplog.text
    store.close()


def test_a_record_changed_during_the_read_is_left_to_the_newer_answer(
    state_store,
):
    desk, rail, _, _ = _paid(state_store)
    rail.states[PID] = SETTLED
    read = rail.ach_state

    def racing(transfer_id):
        rail.ach_state = read
        assert desk.track_ach(transfer_id) == "settled"
        return RETURNED

    rail.ach_state = racing
    assert desk.track_ach(PID) is None
    assert _bodies(state_store, "settlement") == [SETTLEMENT_BODY]
    assert _bodies(state_store, "return") == []
    assert _record(state_store)[PID]["state"] == "settled"


def test_a_lost_answer_links_its_record_to_the_sealed_execution(state_store):
    rail = RecordingRail(RailError("bank: outcome unknown"), balance=50000, ach=True)
    desk, rail, _, _ = _paid(state_store, rail=rail)
    rail.error = None
    rail.listed = [BankTransfer(PID, 20000, "pending_submission", KEY, "")]
    desk.reconcile()
    receipt = desk.proof_receipt(PID)
    record = _record(state_store)[PID]
    assert record["execution_seq"] == receipt["registry"]["entry"]["seq"] == 2
    assert desk.registry.entry(2).kind == "execution"


def test_a_desk_restarted_without_ach_tracks_nothing_and_says_so(state_store, caplog):
    desk, rail, _, _ = _paid(state_store)
    rail.states[PID] = RETURNED
    desk.track_ach(PID)
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    plain = RecordingRail(balance=50000)
    again = _desk(store, bank=plain, now=[NOW])
    assert "ach payments not followed (rail pays no ACH): 0 in flight" in caplog.text
    assert again.intent_receipt("i:000001")["status"] == "returned"
    assert again.lifecycle(PID)["state"] == "returned"
    assert again.track_ach(PID) is None
    store.close()


def test_a_restart_without_ach_names_payments_in_flight(state_store, caplog):
    _paid(state_store)
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    plain = RecordingRail(balance=50000)
    again = _desk(store, bank=plain)
    assert "ach payments not followed (rail pays no ACH): 1 in flight" in caplog.text
    assert again.track_ach(PID) is None
    assert again.reconcile().pending == (f"ach {PID}",)
    assert plain.state_reads == []
    store.close()
