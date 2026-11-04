import logging
import threading
import time

import pytest

from gate.anchor_public import PublicAnchors
from gate.certs import public_key_of
from gate.conftest import (
    BlockingCalendar,
    RecordedCalendars,
    RecordedHeaders,
    recorded_aggregators,
)
from swarm.server import build_server
from swarm.test_receipt import GATE, HOLDER, _pay
from swarm.test_server import FOREIGN, PAIR, _asgi


def _served(make_desk, sign_quote, state_store, with_anchors=True, calendars=None):
    anchors = PublicAnchors(
        state_store,
        public_key_of(GATE),
        recorded_aggregators() if calendars is None else calendars,
        RecordedHeaders({}),
        clock=lambda: 1800002000,
        calendar_for=RecordedCalendars({}).for_uri,
        nonces=lambda: b"\x01" * 16,
    )
    desk, _ = make_desk(
        gate_key=GATE, holder_key=HOLDER, state=state_store, anchors=anchors
    )
    paid = _pay(desk, sign_quote, "acme-991", 20000, "A-991")["payment_id"]
    app = build_server(desk, PAIR, anchors=anchors if with_anchors else None)
    return app.streamable_http_app(), paid, anchors


@pytest.mark.anyio
async def test_anchor_route_runs_one_round(make_desk, sign_quote, state_store):
    app, paid, _ = _served(make_desk, sign_quote, state_store)
    async with _asgi(app) as http:
        resp = await http.post("/api/anchor", json={})
        receipt = await http.get(f"/api/receipt/{paid}")
    assert (resp.status_code, resp.json()) == (
        200,
        {"stamped": 1, "confirmed": 0, "pending": 1, "error": None},
    )
    assert resp.headers["cache-control"] == "no-store"
    assert receipt.json()["public_anchor"]["bitcoin"] is None


@pytest.mark.anyio
@pytest.mark.parametrize(("body", "headers"), [({"run": 1}, {}), ({}, FOREIGN)])
async def test_anchor_route_refuses_other_bodies_and_hosts(
    make_desk, sign_quote, state_store, body, headers
):
    app, _, _ = _served(make_desk, sign_quote, state_store)
    async with _asgi(app) as http:
        resp = await http.post("/api/anchor", json=body, headers=headers)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
async def test_anchor_route_is_off_without_anchors(make_desk, sign_quote, state_store):
    app, _, _ = _served(make_desk, sign_quote, state_store, with_anchors=False)
    async with _asgi(app) as http:
        resp = await http.post("/api/anchor", json={})
    assert (resp.status_code, resp.json()) == (409, {"error": "public anchor off"})


@pytest.mark.anyio
async def test_a_round_that_raises_answers_502_and_keeps_serving(
    make_desk, sign_quote, state_store, caplog, monkeypatch
):
    app, paid, anchors = _served(make_desk, sign_quote, state_store)

    def broken():
        raise ValueError("seal view malformed")

    monkeypatch.setattr(anchors, "try_round", broken)
    async with _asgi(app) as http:
        resp = await http.post("/api/anchor", json={})
        receipt = await http.get(f"/api/receipt/{paid}")
    assert (resp.status_code, resp.json()) == (502, {"error": "anchor failed"})
    assert receipt.status_code == 200
    logged = [
        (r.levelno, r.getMessage()) for r in caplog.records if r.name == "swarm.server"
    ]
    assert logged == [(logging.ERROR, "anchor failed (ValueError)")]


@pytest.mark.anyio
async def test_the_route_is_busy_while_the_background_round_runs(
    make_desk, sign_quote, state_store
):
    held = BlockingCalendar(recorded_aggregators()[0])
    app, _, anchors = _served(
        make_desk,
        sign_quote,
        state_store,
        calendars=[held, *recorded_aggregators()[1:]],
    )
    background = threading.Thread(target=anchors.round)
    background.start()
    try:
        assert held.entered.wait(5)
        started = time.monotonic()
        async with _asgi(app) as http:
            resp = await http.post("/api/anchor", json={})
        # Answered at once, not after the held round ends.
        assert time.monotonic() - started < 5
    finally:
        held.release.set()
        background.join(5)
    assert (resp.status_code, resp.json()) == (409, {"error": "anchor busy"})
    async with _asgi(app) as http:
        again = await http.post("/api/anchor", json={})
    assert (again.status_code, again.json()["stamped"]) == (200, 0)
