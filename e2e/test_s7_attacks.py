"""The bank and the explorer surfaces under attack."""

import hashlib
from collections.abc import Iterator
from typing import Any

import httpx
import httpx2
import pytest

from bank.api import RailError
from bank.conftest import Cassette, RecordingRail, event_body, events_page
from bank.events import CURSOR_KEY, BankEvents
from bank.reconcile import AchState, BankTransfer
from e2e.attack_world import Console
from e2e.test_bank_attacks import BOUND, FIRST_KEY, _pay, _sandbox, _tool
from gate.anchor_public import PublicAnchors
from gate.certs import generate_keypair
from gate.conftest import RecordedCalendars, RecordedHeaders, recorded_aggregators
from swarm import console as console_cli
from swarm.conftest import DEMO_INTENT
from swarm.hub import EventHub
from swarm.server import build_server

FOREIGN = {"host": "evil.example:8765"}
JSON = {"content-type": "application/json"}
NOT_FOUND = (404, {"error": "not found"})
BAD_REQUEST = (400, {"error": "bad request"})
PID = "ach_transfer_t1"
SETTLED_AT = "2027-01-15T09:16:40Z"
RETURNED_AT = "2027-01-16T08:16:40Z"
RETURNED = AchState(
    PID, "returned", SETTLED_AT, "R01", "insufficient_fund", RETURNED_AT
)
RETURNED_DETAIL = (
    "The bank returned payment ach_transfer_t1 (R01 insufficient_fund, "
    "SIMULATED RETURN); the money went back to the paying account. This "
    "intent pays nothing more: sign a new intent to pay again."
)
# Registry leaves of a desk's first two payments; each depends only on its
# entry (seq, kind, body), so every simulated-rail desk has the same two.
LEAF_1 = "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87"
LEAF_2 = "d0ad291d073b7655e945189b684ff45e486ae485817ac3cc97bcaca6c8873e9a"
SINCE = "2026-11-04T08:00:00Z"
NOW = 1793782800


def _two_step(make_desk, serve) -> tuple[str, RecordingRail, bytes]:
    rail = RecordingRail(balance=50000, two_step=True)
    url, _, holder = _sandbox(make_desk, serve, rail)
    return url, rail, holder


def test_the_agent_cannot_make_the_bank_hold_money_without_an_intent(make_desk, serve):
    url, rail, _ = _two_step(make_desk, serve)
    unbound = {k: v for k, v in BOUND.items() if k != "intent_id"}
    assert _tool(url, "quote_payment", unbound) == {
        "status": "denied",
        "reason": "intent: missing",
        "intent_id": None,
    }
    assert rail.holds == []


def test_an_intent_holds_money_at_the_bank_once(make_desk, serve):
    url, rail, _ = _two_step(make_desk, serve)
    assert _tool(url, "quote_payment", BOUND)["status"] == "quoted"
    assert _tool(url, "quote_payment", BOUND) == {
        "status": "denied",
        "reason": "intent: held at the bank",
        "intent_id": "i:000001",
    }
    assert len(rail.holds) == 1


@pytest.mark.parametrize(
    "change",
    [{"amount_cents": 30000}, {"to_account": "mallory-1"}, {"reference": "B-1"}],
    ids=["amount", "payee", "reference"],
)
def test_the_agent_cannot_hold_a_payment_the_holder_did_not_sign(
    make_desk, serve, change
):
    url, rail, _ = _two_step(make_desk, serve)
    assert _tool(url, "quote_payment", {**BOUND, **change}) == {
        "status": "denied",
        "reason": "intent: differs",
        "intent_id": "i:000001",
    }
    assert rail.holds == []
    assert _tool(url, "quote_payment", BOUND)["status"] == "quoted"
    assert len(rail.holds) == 1


@pytest.mark.parametrize(
    ("reason", "intent"),
    [
        ("bank: approved outside the gate", "unsettled"),
        ("bank: canceled at the bank", "signed"),
    ],
)
def test_a_person_at_the_dashboard_never_makes_a_mandate_payment(
    make_desk, serve, reason, intent
):
    url, rail, holder = _two_step(make_desk, serve)
    rail.error = RailError(reason)
    paid = _pay(url, holder)
    assert (paid["status"], paid["reason"], paid["payment_id"]) == (
        "denied",
        reason,
        None,
    )
    assert _tool(url, "get_intent", {"intent_id": "i:000001"})["status"] == intent
    assert [call[2] for call in rail.calls] == [FIRST_KEY]


@pytest.fixture
def returned(make_desk, serve, state_store) -> tuple[str, RecordingRail, bytes]:
    rail = RecordingRail(balance=50000, ach=True)
    url, _, holder = _sandbox(make_desk, serve, rail, state=state_store)
    assert _pay(url, holder)["payment_id"] == PID
    rail.states[PID] = RETURNED
    rail.listed = [BankTransfer(PID, 20000, "returned", FIRST_KEY, "")]
    report = httpx2.post(f"{url}/api/reconcile", json={}).json()
    assert report["resolved"] == [
        "ach_transfer_t1 -> settled",
        "ach_transfer_t1 -> returned R01 (SIMULATED RETURN)",
    ]
    return url, rail, holder


def test_a_returned_payment_never_reopens_its_intent(returned):
    url, rail, holder = returned
    view = _tool(url, "get_intent", {"intent_id": "i:000001"})
    assert (view["status"], view["payment_id"], view["detail"]) == (
        "returned",
        PID,
        RETURNED_DETAIL,
    )
    again = _pay(url, holder)
    assert (again["status"], again["reason"]) == ("denied", "intent: already used")
    assert len(rail.calls) == 1


@pytest.mark.parametrize(
    ("path", "headers", "want"),
    [
        (f"/api/lifecycle/{PID}", FOREIGN, BAD_REQUEST),
        ("/api/lifecycle/pay:000009", {}, NOT_FOUND),
    ],
)
def test_the_lifecycle_answers_only_this_site_and_known_payments(
    returned, path, headers, want
):
    url, _, _ = returned
    answer = httpx2.get(f"{url}{path}", headers=headers)
    assert (answer.status_code, answer.json()) == want


def test_a_bank_event_about_another_transfer_changes_nothing_here(
    make_desk, state_store
):
    rail = RecordingRail(balance=50000, ach=True)
    desk, _ = make_desk(bank=rail, intents=(DEMO_INTENT,), state=state_store)
    elsewhere = event_body(
        1, category="ach_transfer.updated", object_id="sandbox_ach_transfer_other"
    )
    feed = BankEvents(
        Cassette(events_page(elsewhere)).client(), state_store, SINCE, lambda: NOW
    )
    hub = EventHub()
    console_cli.bank_events_round(feed, hub, desk)
    assert [line.source for line in hub.since(0)] == ["bank"]
    assert rail.state_reads == []


@pytest.mark.parametrize(
    "answer",
    [
        (200, {"data": "x", "next_cursor": "c1"}),
        events_page(dict(event_body(1), id=7)),
        events_page(dict(event_body(1), created_at="2026-11-04T08:58:56")),
        httpx.Response(302, headers={"location": "https://evil.example/events"}),
    ],
    ids=["data not a list", "numeric id", "naive time", "redirect"],
)
def test_a_hostile_bank_answer_puts_nothing_on_the_console(
    make_desk, serve, state_store, answer
):
    desk, _ = make_desk()
    hub = EventHub()
    url = serve(build_server(desk, "pair-x", hub=hub).streamable_http_app())
    feed = BankEvents(Cassette(answer).client(), state_store, SINCE, lambda: NOW)
    console_cli.bank_events_round(feed, hub)
    assert httpx2.get(f"{url}/api/lines").json() == []
    assert state_store.get(CURSOR_KEY) is None


def _receipt_hash(copy: dict[str, Any]) -> str:
    return hashlib.sha256(copy["sd"].split("~")[0].encode("ascii")).hexdigest()


@pytest.fixture(scope="module")
def two_payments(tmp_path_factory) -> Iterator[tuple[Console, str]]:
    served = Console(tmp_path_factory.mktemp("lookup")).start()
    try:
        holder = served.pair()
        served.pay(holder)
        served.pay(holder)
        swap = served.post("/api/attack", json={"kind": "payee_swap"}).json()
        yield served, swap["forensic"]["action_hash"]
    finally:
        served.stop()


def test_a_receipt_hash_finds_only_the_auditor_copy(two_payments):
    console, _ = two_payments
    auditor = console.get("/api/receipt/pay:000001").json()
    found = console.get(f"/api/receipt/by-hash/{_receipt_hash(auditor)}")
    assert (found.status_code, found.json()) == (200, auditor)


def test_a_neighbours_leaf_or_a_denied_attempt_finds_nothing(two_payments):
    console, denied_action = two_payments
    second = console.get("/api/receipt/pay:000002").json()
    assert second["registry"]["proof"]["siblings"] == [LEAF_1]
    for digest in (LEAF_1, LEAF_2, denied_action):
        answer = console.get(f"/api/receipt/by-hash/{digest}")
        assert (answer.status_code, answer.json()) == NOT_FOUND


@pytest.mark.parametrize(
    ("shape", "headers"),
    [
        (lambda h: h.upper(), {}),
        (lambda h: h[:63], {}),
        (lambda h: f"{h}?disclose=all", {}),
        (lambda h: h, FOREIGN),
    ],
    ids=["uppercase", "prefix", "holder copy", "foreign host"],
)
def test_a_lookup_that_is_not_one_whole_hash_is_refused(two_payments, shape, headers):
    console, _ = two_payments
    digest = _receipt_hash(console.get("/api/receipt/pay:000001").json())
    answer = console.get(f"/api/receipt/by-hash/{shape(digest)}", headers=headers)
    assert (answer.status_code, answer.json()) == BAD_REQUEST


@pytest.mark.parametrize("headers", [JSON, FOREIGN], ids=["json", "foreign host"])
def test_an_outsider_cannot_spend_calendar_calls(two_payments, headers):
    console, _ = two_payments
    answer = console.post("/api/anchor", content=b"{}", headers=headers)
    want = (409, {"error": "public anchor off"}) if headers is JSON else BAD_REQUEST
    assert (answer.status_code, answer.json()) == want


@pytest.fixture
def anchored(make_desk, sign_quote, serve, state_store):
    gate_priv, gate_pub = generate_keypair()
    calendars = recorded_aggregators()
    anchors = PublicAnchors(
        state_store,
        gate_pub,
        calendars,
        RecordedHeaders({}),
        clock=lambda: 1800002000,
        calendar_for=RecordedCalendars({}).for_uri,
        nonces=lambda: b"\x01" * 16,
    )
    desk, holder = make_desk(gate_key=gate_priv, state=state_store, anchors=anchors)
    quote = desk.quote("acme-991", 20000, "USD", "A-991")
    desk.approve(quote["quote_id"], sign_quote(holder, quote))
    assert desk.confirm(quote["quote_id"])["status"] == "confirmed"
    url = serve(build_server(desk, "pair-x", anchors=anchors).streamable_http_app())
    return url, calendars


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        (b"{}", {"content-type": "text/plain"}),
        (b"{}", {**JSON, "origin": "https://evil.example"}),
        (b"{}", {**JSON, **FOREIGN}),
        (b'{"run": 1}', JSON),
    ],
    ids=["text/plain", "foreign origin", "foreign host", "another body"],
)
def test_a_page_cannot_make_an_anchored_desk_call_the_calendars(
    anchored, body, headers
):
    url, calendars = anchored
    answer = httpx2.post(f"{url}/api/anchor", content=body, headers=headers)
    assert (answer.status_code, answer.json()) == BAD_REQUEST
    assert [c.submitted for c in calendars] == [[]] * len(calendars)
    honest = httpx2.post(f"{url}/api/anchor", json={})
    assert (honest.status_code, honest.json()["stamped"]) == (200, 1)
    assert all(len(c.submitted) == 1 for c in calendars)
