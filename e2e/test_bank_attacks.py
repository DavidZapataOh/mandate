"""The bank answers badly: lost, odd, redirected and differing answers."""

import base64
import hashlib
import json
from typing import Any

import anyio
import httpx
import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import Client
from mcp.types import TextContent

from bank.conftest import Cassette, RecordingRail, recorded
from bank.increase import IncreaseRail
from e2e.attack_world import QUOTE, approval_body, b64, unsigned
from gate.consent import sign_approval
from swarm.conftest import DEMO_INTENT, FakeMeta, message
from swarm.intent import sign_intent
from swarm.server import build_server

ACCOUNTS = {"checking-881": "account_payer", "acme-991": "account_payee"}
FIRST_KEY = "mandate-cert-00000000000000000000000000000002"
NOW = 1800001000
# The certificate lives 300 s; a lookup that finds nothing releases the
# intent only 60 s after that.
RELEASE = NOW + 300 + 60
BOUND = {**QUOTE, "intent_id": "i:000001"}
NOTHING = (200, {"data": [], "next_cursor": None})
HTML = httpx.Response(
    200, text="<html>ok</html>", headers={"content-type": "text/html"}
)
HELD = {
    **recorded("account_transfer")["body"],
    "account_id": "account_payer",
    "destination_account_id": "account_payee",
    "amount": 20000,
    "idempotency_key": FIRST_KEY,
}
UNSETTLED_DETAIL = (
    f"The bank has not confirmed whether transfer {FIRST_KEY} went through "
    "(bank: outcome unknown). This intent pays nothing more until a lookup by "
    "that idempotency key settles it."
)
TOO_EARLY_DETAIL = (
    f"The bank holds no transfer under {FIRST_KEY} yet, and one may still "
    "commit. This intent pays nothing more until its certificate has expired "
    "and a lookup at least 60 s later still finds nothing; try again later."
)


def _tool(url: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    async def call() -> dict[str, Any]:
        async with Client(f"{url}/mcp") as client:
            outcome = await client.call_tool(name, args)
        text = "".join(b.text for b in outcome.content if isinstance(b, TextContent))
        body: dict[str, Any] = json.loads(text)
        return body

    return anyio.run(call)


def _sandbox(make_desk, serve, rail, clock=None, agent=None, state=None):
    desk, holder = make_desk(bank=rail, clock=clock, state=state)
    url = serve(build_server(desk, "pair-x", agent=agent).streamable_http_app())
    intent = {
        "amount_cents": 20000,
        "currency": "USD",
        "recipient": "acme-991",
        "reference": "A-991",
    }
    signed = httpx2.post(
        f"{url}/api/intent",
        json={"intent": intent, "signature": b64(sign_intent(holder, DEMO_INTENT))},
    )
    assert signed.json()["status"] == "signed"
    return url, desk, holder


def _rail(*answers):
    cassette = Cassette("balance_lookup", *answers)
    return IncreaseRail(cassette.client(), ACCOUNTS), cassette


def _pay(url: str, holder: bytes) -> dict[str, Any]:
    quote = _tool(url, "quote_payment", BOUND)
    approval = sign_approval(holder, unsigned(quote))
    approved = httpx2.post(
        f"{url}/api/approve", json=approval_body(quote["quote_id"], approval)
    )
    assert approved.json()["status"] == "approved"
    return _tool(url, "confirm_payment", {"quote_id": quote["quote_id"]})


def _writes(cassette: Cassette) -> list[str]:
    return [
        r.headers["idempotency-key"] for r in cassette.requests if r.method == "POST"
    ]


def test_a_lost_answer_for_money_that_moved_is_a_payment(make_desk, serve):
    rail, cassette = _rail(
        httpx.ReadTimeout("lost"), (200, {"data": [HELD], "next_cursor": None})
    )
    url, _, holder = _sandbox(make_desk, serve, rail)
    paid = _pay(url, holder)
    assert (paid["status"], paid["reason"], paid["payment_id"]) == (
        "confirmed",
        "ok: executed",
        "sandbox_account_transfer_4nicrwgr1kludye5vcc1",
    )
    assert _tool(url, "get_intent", {"intent_id": "i:000001"})["status"] == "paid"
    assert [(r.method, r.url.path) for r in cassette.requests] == [
        ("GET", "/accounts/account_payer/balance"),
        ("POST", "/account_transfers"),
        ("GET", "/account_transfers"),
    ]


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (HTML, "bank: outcome unknown"),
        (
            httpx.Response(307, headers={"location": "https://elsewhere.example/t"}),
            "bank: outcome unknown",
        ),
        ((200, {"id": 5, "status": "complete"}), "bank: transfer differs"),
    ],
    ids=["html 200", "redirect", "a transfer that is not this one"],
)
def test_an_unusable_bank_answer_never_leaves_the_intent_payable_twice(
    make_desk, serve, answer, reason
):
    rail, cassette = _rail(answer, NOTHING)
    url, _, holder = _sandbox(make_desk, serve, rail)
    first = _pay(url, holder)
    assert (first["status"], first["reason"], first["payment_id"]) == (
        "denied",
        reason,
        None,
    )
    view = _tool(url, "get_intent", {"intent_id": "i:000001"})
    assert (view["status"], view["idempotency_key"]) == ("unsettled", FIRST_KEY)
    again = _pay(url, holder)
    assert (again["status"], again["reason"]) == ("denied", "intent: unsettled")
    assert _writes(cassette) == [FIRST_KEY]
    assert {r.url.host for r in cassette.requests} == {"sandbox.increase.com"}


def _start(url: str, holder: bytes) -> httpx2.Response:
    body = json.dumps({"intent_id": "i:000001"}).encode()
    digest = hashlib.sha256(body).hexdigest()
    signed = Ed25519PrivateKey.from_private_bytes(holder).sign(
        f"mandate/agent-start/v1\n{digest}".encode()
    )
    proof = base64.urlsafe_b64encode(signed).decode().rstrip("=")
    headers = {"content-type": "application/json", "x-mandate-device-sig": proof}
    return httpx2.post(f"{url}/api/agent/start", content=body, headers=headers)


def test_an_unknown_outcome_releases_the_intent_only_after_its_window(make_desk, serve):
    now = [NOW]
    # A lookup that finds nothing reads the account transfers, then the ACH
    # transfers, under the key.
    rail, cassette = _rail(
        httpx.ReadTimeout("lost"),
        httpx.ReadTimeout("lost again"),
        *(NOTHING,) * 4,
    )
    agent = FakeMeta([message("I will not pay.")])
    url, _, holder = _sandbox(make_desk, serve, rail, lambda: now[0], agent)
    assert _pay(url, holder)["reason"] == "bank: outcome unknown"
    assert _tool(url, "get_intent", {"intent_id": "i:000001"})["detail"] == (
        UNSETTLED_DETAIL
    )
    now[0] = RELEASE - 1
    early = _start(url, holder)
    assert (early.status_code, early.json()) == (409, {"error": TOO_EARLY_DETAIL})
    now[0] = RELEASE
    assert _start(url, holder).status_code == 202
    assert _writes(cassette) == [FIRST_KEY]
    assert [r.url.path for r in cassette.requests][-4:] == [
        "/account_transfers",
        "/ach_transfers",
        "/account_transfers",
        "/ach_transfers",
    ]


def test_an_unexpected_bank_error_keeps_the_intent_and_its_secret(make_desk, serve):
    rail = RecordingRail(AttributeError("acme-991 secret detail"), balance=50000)
    url, _, holder = _sandbox(make_desk, serve, rail)
    first = _pay(url, holder)
    assert (first["reason"], "secret" in json.dumps(first)) == (
        "bank: outcome unknown",
        False,
    )
    assert _pay(url, holder)["reason"] == "intent: unsettled"
    assert len(rail.calls) == 1


def test_a_listing_that_is_not_transfers_writes_nothing(make_desk, serve, state_store):
    cassette = Cassette((200, {"data": "x", "next_cursor": None}))
    rail = IncreaseRail(cassette.client(), ACCOUNTS)
    desk, _ = make_desk(bank=rail, state=state_store)
    url = serve(build_server(desk, "pair-x").streamable_http_app())
    report = httpx2.post(f"{url}/api/reconcile", json={}).json()
    assert (report["error"], report["transfers"], report["unbacked"]) == (
        "bank: unavailable",
        0,
        [],
    )
    assert state_store.entries() == []
