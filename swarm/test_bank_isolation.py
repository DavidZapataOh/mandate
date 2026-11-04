import json

import pytest
from mcp import Client

from bank.conftest import SENTINEL_KEY, Cassette, recorded
from bank.increase import IncreaseRail
from swarm.conftest import DEMO_INTENT
from swarm.hub import EventHub
from swarm.server import build_server
from swarm.test_server import ARGS, PAIR, _asgi

ACCOUNTS = {"checking-881": "account_payer", "acme-991": "account_payee"}


@pytest.mark.anyio
async def test_the_bank_key_reaches_the_bank_and_nothing_else(make_desk, sign_quote):
    cassette = Cassette("balance_lookup", "account_transfer")
    rail = IncreaseRail(cassette.client(), ACCOUNTS)
    hub = EventHub()
    desk, holder = make_desk(publish=hub.publish, intents=(DEMO_INTENT,), bank=rail)
    srv = build_server(desk, PAIR, hub=hub)
    seen = []
    async with Client(srv) as client:
        bound = {**ARGS, "intent_id": "i:000001"}
        quoted = (await client.call_tool("quote_payment", bound)).content[0].text
        q = json.loads(quoted)
        desk.approve(q["quote_id"], sign_quote(holder, q))
        paid = (
            (await client.call_tool("confirm_payment", {"quote_id": q["quote_id"]}))
            .content[0]
            .text
        )
        payment_id = json.loads(paid)["payment_id"]
        for name, args in (
            ("get_payment_status", {"quote_id": q["quote_id"]}),
            ("get_receipt", {"payment_id": payment_id}),
        ):
            seen.append((await client.call_tool(name, args)).content[0].text)
    seen += [quoted, paid, repr(rail), repr(desk.bank)]
    async with _asgi(srv.streamable_http_app()) as http:
        for path in (
            "/api/lines",
            "/api/forensic/3",
            "/api/pending",
            "/api/keys",
            "/api/registry",
            f"/api/receipt/{payment_id}",
        ):
            seen.append((await http.get(path)).text)
    assert payment_id == recorded("account_transfer")["body"]["id"]
    assert all(SENTINEL_KEY not in text for text in seen)
    assert [r.url.path for r in cassette.requests] == [
        "/accounts/account_payer/balance",
        "/account_transfers",
    ]
    for sent in cassette.requests:
        assert sent.headers["authorization"] == f"Bearer {SENTINEL_KEY}"
