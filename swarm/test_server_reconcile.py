import base64
import sqlite3
import threading

import anyio
import pytest

from bank.conftest import SENTINEL_KEY, RecordingRail
from swarm.desk import PaymentDesk
from swarm.hub import EventHub
from swarm.server import build_server
from swarm.test_server import FOREIGN, PAIR, _asgi


def _app(make_desk, state_store, bank=None):
    hub = EventHub()
    desk, _ = make_desk(publish=hub.publish, bank=bank, state=state_store)
    return build_server(desk, PAIR, hub=hub).streamable_http_app()


@pytest.mark.anyio
async def test_reconcile_route_reports_without_the_key(make_desk, state_store):
    rail = RecordingRail(balance=50000)
    async with _asgi(_app(make_desk, state_store, rail)) as http:
        resp = await http.post("/api/reconcile", json={})
        prov = await http.get("/api/provenance")
    assert resp.status_code == 200
    assert resp.json() == {
        "rail": "sandbox", "provider": "increase", "since": "2027-01-15T08:16:40Z",
        "checked_at": 1800001000, "transfers": 0, "certified": 0, "unbacked": [],
        "missing": [], "resolved": [], "pending": [], "paid_twice": [],
        "unreadable": [], "error": None,
    }  # fmt: skip
    assert resp.headers["cache-control"] == "no-store"
    assert prov.json()["bank"] == resp.json()
    assert SENTINEL_KEY not in resp.text + prov.text


@pytest.mark.anyio
@pytest.mark.parametrize(("body", "headers"), [({"run": 1}, {}), ({}, FOREIGN)])
async def test_reconcile_route_refuses_other_bodies_and_hosts(
    make_desk, state_store, body, headers
):
    async with _asgi(_app(make_desk, state_store)) as http:
        resp = await http.post("/api/reconcile", json=body, headers=headers)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
async def test_reconcile_route_without_a_store_still_lists_the_simulated_ledger(
    make_desk,
):
    hub = EventHub()
    desk, _ = make_desk(publish=hub.publish)
    app = build_server(desk, PAIR, hub=hub).streamable_http_app()
    async with _asgi(app) as http:
        resp = await http.post("/api/reconcile", json={})
    assert (resp.json()["rail"], resp.json()["since"]) == ("simulated", "")


@pytest.mark.anyio
async def test_reconcile_route_names_a_rail_that_cannot_list(
    make_desk, state_store, monkeypatch
):
    monkeypatch.delattr(RecordingRail, "transfers")
    async with _asgi(_app(make_desk, state_store, RecordingRail())) as http:
        resp = await http.post("/api/reconcile", json={})
    assert (resp.status_code, resp.json()) == (409, {"error": "reconcile unavailable"})


HOLDER = base64.b64encode(b"\x07" * 32).decode()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("path", "body"),
    [("/api/reconcile", {}), ("/api/holder", {"public_key": HOLDER, "pairing": PAIR})],
)
async def test_a_failed_commit_answers_a_clean_error(
    make_desk, state_store, monkeypatch, path, body
):
    hub = EventHub()
    desk, _ = make_desk(register=False, publish=hub.publish, state=state_store)
    app = build_server(desk, PAIR, hub=hub).streamable_http_app()

    def locked(*_args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(state_store, "put", locked)
    async with _asgi(app) as http:
        resp = await http.post(path, json=body)
    assert (resp.status_code, resp.json()) == (503, {"error": "state: unavailable"})
    assert "Traceback" not in resp.text


class _Gated(RecordingRail):
    """A rail whose listing waits until the test lets it answer."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.started = threading.Event()
        self.release = threading.Event()
        self.done = False

    def transfers(self, from_acct, since):
        self.started.set()
        self.release.wait(5)
        self.done = True
        return super().transfers(from_acct, since)


@pytest.mark.anyio
async def test_routes_answer_while_a_slow_listing_runs(make_desk, state_store):
    rail = _Gated(balance=50000)
    first = {}
    async with _asgi(_app(make_desk, state_store, rail)) as http:
        async with anyio.create_task_group() as tasks:

            async def run():
                first["resp"] = await http.post("/api/reconcile", json={})

            tasks.start_soon(run)
            assert await anyio.to_thread.run_sync(rail.started.wait, 5)
            busy = await http.post("/api/reconcile", json={})
            prov = await http.get("/api/provenance")
            pending = await http.get("/api/pending")
            answered_meanwhile = not rail.done
            rail.release.set()
    assert answered_meanwhile
    assert (busy.status_code, busy.json()) == (409, {"error": "reconcile busy"})
    assert (prov.status_code, pending.status_code) == (200, 200)
    assert first["resp"].status_code == 200


@pytest.mark.anyio
async def test_a_round_that_fails_answers_a_clean_error(
    make_desk, state_store, monkeypatch
):
    def broken(self, ledger):
        raise AttributeError("data")

    monkeypatch.setattr(PaymentDesk, "_reconcile_bank", broken)
    async with _asgi(_app(make_desk, state_store, RecordingRail())) as http:
        resp = await http.post("/api/reconcile", json={})
        prov = await http.get("/api/provenance")
    assert (resp.status_code, resp.json()) == (502, {"error": "reconcile failed"})
    assert "Traceback" not in resp.text
    assert prov.json()["bank"]["error"] == "reconcile: failed"
