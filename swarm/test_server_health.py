import itertools
import re

import pytest

from bank.api import RailError
from bank.conftest import SENTINEL_KEY, WEBHOOK_SECRET, Cassette, RecordingRail
from bank.increase import IncreaseRail
from swarm.card import WEBHOOK_PATH, card_webhook_app
from swarm.console import AttackRunner, DeployRunner
from swarm.hub import EventHub
from swarm.server import build_server
from swarm.test_server import FOREIGN, PAIR, _asgi

ACCOUNTS = {"checking-881": "account_payer", "acme-991": "account_payee"}
NOW = 1800001000
GATE = b"\x01" * 32


async def _health(desk):
    async with _asgi(build_server(desk, PAIR).streamable_http_app()) as http:
        return await http.get("/api/health")


@pytest.mark.anyio
async def test_health_answers_without_asking_the_bank(make_desk):
    cassette = Cassette()
    desk, _ = make_desk(bank=IncreaseRail(cassette.client(), ACCOUNTS))
    resp = await _health(desk)
    assert resp.json() == {"rail": "sandbox", "reconciled_at": None, "bank": None}
    assert resp.headers["cache-control"] == "no-store"
    assert cassette.requests == []
    assert SENTINEL_KEY not in resp.text


@pytest.mark.anyio
async def test_health_names_the_last_reconciliation(make_desk):
    desk, _ = make_desk()
    desk.reconcile()
    resp = await _health(desk)
    assert resp.json() == {"rail": "simulated", "reconciled_at": NOW, "bank": None}


@pytest.mark.anyio
async def test_health_names_a_bank_that_did_not_answer(make_desk, state_store):
    rail = RecordingRail()
    rail.listed_error = RailError("bank: unavailable")
    desk, _ = make_desk(bank=rail, state=state_store)
    desk.reconcile()
    resp = await _health(desk)
    assert resp.json() == {
        "rail": "sandbox",
        "reconciled_at": NOW,
        "bank": "bank: unavailable",
    }
    assert rail.calls == []


@pytest.mark.anyio
async def test_every_route_refuses_a_foreign_host(make_desk, tmp_path):
    hub = EventHub()
    desk, _ = make_desk(publish=hub.publish, gate_key=GATE)
    count = itertools.count(1)

    def nonce():
        return f"atk{next(count):029d}"

    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html>")
    srv = build_server(
        desk, PAIR, hub=hub, console_dir=dist,
        attacks=AttackRunner(desk, GATE, hub, lambda: NOW, nonce),
        deploys=DeployRunner(GATE, hub, lambda: NOW, nonce),
    )  # fmt: skip
    app = srv.streamable_http_app()
    answers = {}
    async with _asgi(app) as http:
        # /mcp keeps the SDK's own Host check (421); the e2e covers it.
        for route in (r for r in app.routes if r.path != "/mcp"):
            path = re.sub(r"\{[^}]+\}", "x", route.path)
            for method in sorted(route.methods - {"HEAD"}):
                resp = await http.request(method, path, headers=FOREIGN)
                answers[f"{method} {route.path}"] = (resp.status_code, resp.json())
    assert {
        "GET /api/health", "GET /api/events", "GET /app/fonts/{name}",
        "POST /api/anchor", "GET /api/receipt/by-hash/{digest}",
        "GET /api/lifecycle/{payment_id}",
    } <= answers.keys()  # fmt: skip
    refused = (400, {"error": "bad request"})
    assert {route: got for route, got in answers.items() if got != refused} == {}


class _NeverAuthorizes:
    def stamp(self):
        return 0.0

    def handle(self, decision_id, received):
        raise AssertionError("an unsigned webhook reached the authorizer")


@pytest.mark.anyio
async def test_the_card_webhook_answers_no_host_without_the_bank_signature():
    # The tunnel publishes the card port under a name of its own, so the
    # signature, not Host, admits a request.
    cassette = Cassette()
    app = card_webhook_app(cassette.client(), _NeverAuthorizes(), WEBHOOK_SECRET)
    answers = {}
    async with _asgi(app) as http:
        for route in app.routes:
            for method in sorted(route.methods - {"HEAD"}):
                resp = await http.request(
                    method, route.path, headers=FOREIGN, content=b"{}"
                )
                answers[f"{method} {route.path}"] = (resp.status_code, resp.json())
    assert answers == {f"POST {WEBHOOK_PATH}": (401, {"error": "webhook: unsigned"})}
    assert cassette.requests == []
