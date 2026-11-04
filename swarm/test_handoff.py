import base64
import hashlib
import json
import time

import anyio
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bank.api import RailError
from bank.conftest import RecordingRail
from gate.certs import generate_keypair
from swarm.conftest import DEMO_INTENT, REASONING, message, tool_call
from swarm.console_line import console_line_json
from swarm.handoff import CONFIRM_REQUEST, QUOTE_REQUEST, AgentHandoff
from swarm.intent import sign_intent
from swarm.meta_client import MetaAPIError
from swarm.server import build_server
from swarm.test_server import PAIR, _approval_json, _asgi

QUOTE = {
    "intent_id": "i:000001",
    "to_account": "acme-991",
    "amount_cents": 20000,
    "currency": "USD",
    "reference": "A-991",
}


def _paying_agent(fake_meta, quote=QUOTE):
    return fake_meta(
        [REASONING, tool_call({"intent_id": "i:000001"}, "get_intent", "c1")],
        [tool_call(quote, "quote_payment", "c2")],
        [message("Quoted q:000001.")],
        [tool_call({"quote_id": "q:000001"}, "confirm_payment", "c3")],
        [message("Confirmed.")],
    )


def _start_request(key, intent_id="i:000001", body=None, domain="agent-start"):
    raw = json.dumps({"intent_id": intent_id}).encode()
    digest = hashlib.sha256(raw if body is None else body).hexdigest()
    message = f"mandate/{domain}/v1\n{digest}".encode()
    signature = Ed25519PrivateKey.from_private_bytes(key).sign(message)
    return {
        "content": raw,
        "headers": {
            "content-type": "application/json",
            "x-mandate-device-sig": base64.urlsafe_b64encode(signature)
            .decode()
            .rstrip("="),
        },
    }


def _until(handoff, state, timeout=5.0):
    deadline = time.monotonic() + timeout
    while handoff.status()["state"] != state:
        assert time.monotonic() < deadline, handoff.status()
        time.sleep(0.01)
    return handoff.status()


def _handoff(desk, meta, **kwargs):
    return AgentHandoff(meta, build_server(desk, PAIR), desk, poll_s=0.01, **kwargs)


def test_agent_pays_from_the_intent_id_alone(make_desk, fake_meta, sign_quote):
    desk, holder = make_desk(intents=(DEMO_INTENT,))
    meta = _paying_agent(fake_meta)
    handoff = _handoff(desk, meta)
    assert handoff.start("i:000001") == {
        "state": "quoting",
        "intent_id": "i:000001",
        "quote_id": None,
        "detail": "Muse Spark is quoting intent i:000001; it holds only this id.",
    }
    waiting = _until(handoff, "waiting")
    assert waiting["detail"] == "Quote q:000001 is waiting for your approval."
    desk.approve("q:000001", sign_quote(holder, desk.status("q:000001")))
    assert _until(handoff, "done") == {
        "state": "done",
        "intent_id": "i:000001",
        "quote_id": "q:000001",
        "detail": "Paid: pay:000001.",
    }
    assert desk.bank.get_balance("acme-991") == 20000
    asked = [r["input"][0] for r in (meta.requests[0], meta.requests[3])]
    assert asked == [
        {"role": "user", "content": QUOTE_REQUEST.format(intent_id="i:000001")},
        {"role": "user", "content": CONFIRM_REQUEST.format(quote_id="q:000001")},
    ]


def test_a_swapped_payee_dies_at_the_gate(make_desk, fake_meta, sign_quote):
    desk, holder = make_desk(intents=(DEMO_INTENT,))
    meta = _paying_agent(fake_meta, {**QUOTE, "to_account": "evil-666"})
    handoff = _handoff(desk, meta)
    handoff.start("i:000001")
    _until(handoff, "waiting")
    desk.approve("q:000001", sign_quote(holder, desk.status("q:000001")))
    failed = _until(handoff, "failed")
    assert failed["detail"] == "Not paid: recipient differs from intent."
    assert desk.bank.get_balance("checking-881") == 50000


@pytest.mark.parametrize(
    ("outputs", "detail"),
    [
        (
            [[message("I would rather not.")]],
            "Muse Spark did not quote intent i:000001.",
        ),
        (
            [MetaAPIError("HTTP 500: down")],
            "Muse Spark call failed: HTTP 500: down",
        ),
    ],
)
def test_runs_that_never_quote_fail(make_desk, fake_meta, outputs, detail):
    desk, _ = make_desk(intents=(DEMO_INTENT,))
    handoff = _handoff(desk, fake_meta(*outputs))
    handoff.start("i:000001")
    assert _until(handoff, "failed")["detail"] == detail
    assert desk.pending() == []


def test_unapproved_quote_is_never_confirmed(make_desk, fake_meta):
    desk, _ = make_desk(intents=(DEMO_INTENT,))
    meta = _paying_agent(fake_meta)
    handoff = _handoff(desk, meta, wait_s=0.0)
    handoff.start("i:000001")
    failed = _until(handoff, "failed")
    assert failed["detail"] == "Quote q:000001 was not approved: quoted."
    assert len(meta.requests) == 3


@pytest.mark.anyio
async def test_start_route_refusals(make_desk, fake_meta):
    desk, holder = make_desk(intents=(DEMO_INTENT,))
    app = build_server(desk, PAIR, agent=_paying_agent(fake_meta)).streamable_http_app()
    bare = build_server(desk, PAIR).streamable_http_app()
    async with _asgi(app) as http, _asgi(bare) as plain:
        unknown = await http.post(
            "/api/agent/start", **_start_request(holder, "i:000009")
        )
        first = await http.post("/api/agent/start", **_start_request(holder))
        busy = await http.post("/api/agent/start", **_start_request(holder))
        absent = await plain.post("/api/agent/start", **_start_request(holder))
        idle = await plain.get("/api/agent")
    assert (unknown.status_code, unknown.json()) == (404, {"error": "unknown intent"})
    assert (first.status_code, first.json()["state"]) == (202, "quoting")
    assert (busy.status_code, busy.json()) == (409, {"error": "busy"})
    assert absent.status_code == idle.status_code == 503


@pytest.mark.anyio
async def test_start_needs_the_paired_device_before_any_model_call(
    make_desk, fake_meta
):
    desk, holder = make_desk(intents=(DEMO_INTENT,))
    meta = _paying_agent(fake_meta)
    app = build_server(desk, PAIR, agent=meta).streamable_http_app()
    stranger = bytes([9]) * 32
    other = json.dumps({"intent_id": "i:000002"}).encode()
    attempts = [
        {
            "content": b'{"intent_id": "i:000001"}',
            "headers": {"content-type": "application/json"},
        },
        _start_request(stranger),
        _start_request(holder, body=other),
        _start_request(holder, domain="intent-draft"),
    ]
    async with _asgi(app) as http:
        refused = [await http.post("/api/agent/start", **a) for a in attempts]
        idle = (await http.get("/api/agent")).json()["state"]
    assert [(r.status_code, r.json()) for r in refused] == [
        (401, {"error": "not the paired device"})
    ] * 4
    assert (idle, meta.requests) == ("idle", [])


def _b64(raw):
    return base64.b64encode(raw).decode()


@pytest.mark.anyio
async def test_no_holder_secret_reaches_the_agent_or_a_line(
    make_desk, fake_meta, sign_quote
):
    lines = []
    desk, _ = make_desk(register=False, publish=lines.append)
    holder_priv, holder_pub = generate_keypair()
    agent = _paying_agent(fake_meta)
    app = build_server(desk, PAIR, agent=agent).streamable_http_app()
    signature = _b64(sign_intent(holder_priv, DEMO_INTENT))
    intent = {
        "amount_cents": 20000,
        "currency": "USD",
        "recipient": "acme-991",
        "reference": "A-991",
    }
    cookie = {"cookie": "session=COOKIE-SECRET-7"}
    async with _asgi(app) as http:
        paired = await http.post(
            "/api/holder", json={"public_key": _b64(holder_pub), "pairing": PAIR}
        )
        signed = await http.post(
            "/api/intent",
            json={"intent": intent, "signature": signature},
            headers=cookie,
        )
        request = _start_request(holder_priv)
        request["headers"].update(cookie)
        await http.post("/api/agent/start", **request)
        handoff_state = None
        deadline = time.monotonic() + 5
        while handoff_state != "waiting":
            assert time.monotonic() < deadline
            await anyio.sleep(0.01)
            handoff_state = (await http.get("/api/agent")).json()["state"]
        approval = _approval_json(
            "q:000001", sign_quote(holder_priv, desk.status("q:000001"))
        )
        await http.post("/api/approve", json=approval, headers=cookie)
        while handoff_state != "done":
            assert time.monotonic() < deadline
            await anyio.sleep(0.01)
            handoff_state = (await http.get("/api/agent")).json()["state"]
    assert paired.json() == {"registered": True}
    receipt = signed.json()
    agent_side = json.dumps(agent.requests, default=str)
    wire = "".join(console_line_json(line) for line in lines)
    secrets = (
        PAIR,
        "COOKIE-SECRET-7",
        _b64(holder_pub),
        signature,
        approval["signature"],
        approval["key_signature"],
        receipt["state"]["signature"],
        receipt["bank_key"],
        "50000",
        "balance_cents",
    )
    assert [s for s in secrets if s in agent_side or s in wire] == []
    assert "i:000001" in agent_side
    assert desk.bank.get_balance("acme-991") == 20000


def test_an_unexpected_error_frees_the_slot(make_desk, fake_meta):
    desk, _ = make_desk(intents=(DEMO_INTENT,))
    handoff = _handoff(desk, fake_meta([RuntimeError("boom")]))
    handoff.start("i:000001")
    assert _until(handoff, "failed")["detail"] == "Muse Spark run failed."


UNSETTLED_DETAIL = (
    "The bank has not confirmed whether transfer "
    "mandate-cert-00000000000000000000000000000002 went through "
    "(bank: outcome unknown). This intent pays nothing more until a lookup "
    "by that idempotency key settles it."
)


def _unsettled_run(make_desk, fake_meta, sign_quote, clock=None):
    rail = RecordingRail(RailError("bank: outcome unknown"), balance=50000)
    desk, holder = make_desk(intents=(DEMO_INTENT,), bank=rail, clock=clock)
    handoff = _handoff(desk, _paying_agent(fake_meta))
    handoff.start("i:000001")
    _until(handoff, "waiting")
    desk.approve("q:000001", sign_quote(holder, desk.status("q:000001")))
    return desk, rail, handoff, _until(handoff, "failed")


def test_an_unknown_bank_outcome_is_never_reported_as_not_paid(
    make_desk, fake_meta, sign_quote
):
    _, _, _, failed = _unsettled_run(make_desk, fake_meta, sign_quote)
    assert failed["detail"] == UNSETTLED_DETAIL


@pytest.mark.parametrize(
    ("found", "answer"),
    [
        (RailError("bank: outcome unknown"), {"error": UNSETTLED_DETAIL}),
        (True, {"error": "intent already paid: account_transfer_t1"}),
    ],
)
def test_an_unsettled_intent_is_looked_up_before_another_run(
    make_desk, fake_meta, sign_quote, found, answer
):
    desk, rail, handoff, _ = _unsettled_run(make_desk, fake_meta, sign_quote)
    rail.found = found
    assert handoff.start("i:000001") == answer
    assert len(rail.lookups) == 1
    assert len(rail.calls) == 1


def test_an_intent_the_bank_never_paid_is_released_for_a_new_run(
    make_desk, fake_meta, sign_quote
):
    now = [1800001000]
    desk, rail, _, _ = _unsettled_run(
        make_desk, fake_meta, sign_quote, clock=lambda: now[0]
    )
    again = _handoff(desk, _paying_agent(fake_meta))
    assert "try again later" in again.start("i:000001")["error"]
    now[0] += 60
    assert again.start("i:000001")["state"] == "quoting"
    assert len(rail.lookups) == 2


@pytest.mark.anyio
async def test_the_holder_page_hears_why_an_unsettled_intent_cannot_run(
    make_desk, fake_meta, sign_quote
):
    rail = RecordingRail(RailError("bank: outcome unknown"), balance=50000)
    desk, holder = make_desk(intents=(DEMO_INTENT,), bank=rail)
    q = desk.quote("acme-991", 20000, "USD", "A-991", "i:000001")
    desk.approve(q["quote_id"], sign_quote(holder, q))
    desk.confirm(q["quote_id"])
    rail.found = RailError("bank: outcome unknown")
    meta = _paying_agent(fake_meta)
    app = build_server(desk, PAIR, agent=meta).streamable_http_app()
    async with _asgi(app) as http:
        refused = await http.post("/api/agent/start", **_start_request(holder))
    assert (refused.status_code, refused.json()) == (409, {"error": UNSETTLED_DETAIL})
    assert meta.requests == []
