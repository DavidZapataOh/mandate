import base64
import hashlib
import json

import pytest
from mcp import Client

from bank.conftest import Cassette, recorded
from bank.increase import IncreaseRail
from swarm.conftest import DEMO_INTENT
from swarm.server import build_server
from swarm.test_receipt import AUDITOR, GATE, HOLDER, _pay
from swarm.test_receipt_lookup import (
    ACTION_HASH,
    FIRST_LEAF,
    RECEIPT_HASH,
    SECOND_LEAF,
)
from swarm.test_server import ARGS, FOREIGN, PAIR, _asgi, _http

NOT_FOUND = (404, {"error": "not found"})
BAD_REQUEST = (400, {"error": "bad request"})
ACCOUNTS = {"checking-881": "account_payer", "acme-991": "account_payee"}
TRANSFER = "sandbox_account_transfer_4nicrwgr1kludye5vcc1"
# The recorded transfer, as the bank holds it for this desk's first payment.
HELD = {
    **recorded("account_transfer")["body"],
    "account_id": "account_payer",
    "destination_account_id": "account_payee",
    "amount": 20000,
    "idempotency_key": "mandate-cert-00000000000000000000000000000002",
}


def _paid_twice(make_desk, sign_quote):
    desk, _ = make_desk(gate_key=GATE, holder_key=HOLDER)
    _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    _pay(desk, sign_quote, "acme-991", 20000, "A-992")
    return desk


def _answer(resp):
    return (resp.status_code, resp.json())


@pytest.mark.anyio
@pytest.mark.parametrize("digest", [RECEIPT_HASH, ACTION_HASH])
async def test_a_hash_finds_the_auditor_copy(make_desk, sign_quote, digest):
    desk = _paid_twice(make_desk, sign_quote)
    async with _http(desk) as http:
        resp = await http.get(f"/api/receipt/by-hash/{digest}")
    assert _answer(resp) == (200, json.loads(AUDITOR.read_text()))


@pytest.mark.anyio
@pytest.mark.parametrize("digest", [FIRST_LEAF, SECOND_LEAF, "ab" * 32])
async def test_a_leaf_or_unknown_hash_finds_nothing(make_desk, sign_quote, digest):
    desk = _paid_twice(make_desk, sign_quote)
    async with _http(desk) as http:
        resp = await http.get(f"/api/receipt/by-hash/{digest}")
        unknown = await http.get(f"/api/receipt/by-hash/{'cd' * 32}")
    assert _answer(resp) == NOT_FOUND
    # A leaf hash must not be told apart from a hash nobody ever made.
    assert (resp.content, dict(resp.headers)) == (
        unknown.content,
        dict(unknown.headers),
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "digest",
    [
        RECEIPT_HASH[:63],
        RECEIPT_HASH + "0",
        RECEIPT_HASH.upper(),
        "0x" + RECEIPT_HASH[2:],
    ],
)
async def test_only_a_whole_lowercase_hash_is_looked_up(make_desk, sign_quote, digest):
    desk = _paid_twice(make_desk, sign_quote)
    async with _http(desk) as http:
        resp = await http.get(f"/api/receipt/by-hash/{digest}")
    assert _answer(resp) == BAD_REQUEST


@pytest.mark.anyio
@pytest.mark.parametrize("query", ["?disclose=all", "?x=1"])
async def test_a_hash_lookup_takes_no_query(make_desk, sign_quote, query):
    desk = _paid_twice(make_desk, sign_quote)
    async with _http(desk) as http:
        resp = await http.get(f"/api/receipt/by-hash/{RECEIPT_HASH}{query}")
    assert _answer(resp) == BAD_REQUEST


@pytest.mark.anyio
async def test_a_hash_lookup_refuses_a_foreign_host(make_desk, sign_quote):
    desk = _paid_twice(make_desk, sign_quote)
    async with _http(desk) as http:
        resp = await http.get(f"/api/receipt/by-hash/{RECEIPT_HASH}", headers=FOREIGN)
    assert _answer(resp) == BAD_REQUEST


def _claims(token):
    part = token.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    return payload["events"]["urn:mandate:secevent:cert:v1"]


@pytest.mark.anyio
async def test_a_sandbox_payment_is_found_by_its_transfer_id_and_hashes(
    make_desk, sign_quote
):
    rail = IncreaseRail(Cassette("balance_lookup", (200, HELD)).client(), ACCOUNTS)
    desk, holder = make_desk(intents=(DEMO_INTENT,), bank=rail)
    srv = build_server(desk, PAIR)
    async with Client(srv) as client:
        bound = {**ARGS, "intent_id": "i:000001"}
        q = json.loads((await client.call_tool("quote_payment", bound)).content[0].text)
        desk.approve(q["quote_id"], sign_quote(holder, q))
        await client.call_tool("confirm_payment", {"quote_id": q["quote_id"]})
    async with _asgi(srv.streamable_http_app()) as http:
        by_id = await http.get(f"/api/receipt/{TRANSFER}")
        shared = by_id.json()
        token = shared["sd"].split("~")[0]
        receipt_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        action_hash = _claims(shared["certificate"])["action_hash"]
        by_receipt = await http.get(f"/api/receipt/by-hash/{receipt_hash}")
        by_action = await http.get(f"/api/receipt/by-hash/{action_hash}")
    assert (by_id.status_code, shared["payment_id"]) == (200, TRANSFER)
    assert shared["sd"].count("~") == 1
    assert _answer(by_receipt) == (200, shared)
    assert _answer(by_action) == (200, shared)
