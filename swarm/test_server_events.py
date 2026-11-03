import json
import threading
import time

import anyio
import httpx2
import pytest

from swarm.console_line import ConsoleLine, console_line_json, read_console_line
from swarm.hub import EventHub
from swarm.server import build_server
from swarm.test_server import FOREIGN, PAIR, _asgi


def _line(agent):
    subject = {"agent": agent, "tool": "edit_file", "targets": [], "tool_use_id": None}
    return ConsoleLine(0, "hook", None, None, subject, None)


def _hub(*agents):
    hub = EventHub()
    for agent in agents:
        hub.publish(_line(agent))
    return hub


def _app(desk, hub):
    return build_server(desk, PAIR, hub=hub).streamable_http_app()


def _frames(response, stop):
    frames, fields = [], {}
    for raw in response.iter_lines():
        if raw:
            key, _, value = raw.partition(": ")
            fields[key] = value
            continue
        frames.append(fields)
        fields = {}
        if stop(frames):
            return frames
    return frames


@pytest.mark.anyio
async def test_lines_since(make_desk):
    desk, _ = make_desk()
    hub = _hub("a", "b", "c")
    async with _asgi(_app(desk, hub)) as http:
        resp = await http.get("/api/lines?since=1")
    assert resp.headers["content-type"].startswith("application/json")
    lines = [read_console_line(json.dumps(item)) for item in resp.json()]
    assert lines == hub.since(1)
    assert [line.subject["agent"] for line in lines] == ["b", "c"]


@pytest.mark.anyio
@pytest.mark.parametrize("since", ["x", "-1", "1.5", "٣"])
async def test_lines_rejects_bad_since(make_desk, since):
    desk, _ = make_desk()
    async with _asgi(_app(desk, _hub("a"))) as http:
        resp = await http.get("/api/lines", params={"since": since})
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
async def test_forensic_route_returns_the_line(make_desk):
    desk, _ = make_desk()
    hub = _hub("a", "b")
    async with _asgi(_app(desk, hub)) as http:
        found = await http.get("/api/forensic/2")
        gone = await http.get("/api/forensic/9")
        bad = await http.get("/api/forensic/x")
    assert found.text == console_line_json(hub.get(2))
    assert (gone.status_code, gone.json()) == (404, {"error": "not found"})
    assert bad.status_code == 404


@pytest.mark.anyio
async def test_hub_routes_absent_without_hub(make_desk):
    desk, _ = make_desk()
    async with _asgi(build_server(desk, PAIR).streamable_http_app()) as http:
        resp = await http.get("/api/lines")
    assert resp.status_code == 404


@pytest.mark.anyio
@pytest.mark.parametrize("path", ["/api/events", "/api/lines", "/api/forensic/1"])
async def test_hub_routes_reject_foreign_host(make_desk, path):
    desk, _ = make_desk()
    async with _asgi(_app(desk, _hub("a"))) as http:
        resp = await http.get(path, headers=FOREIGN)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
async def test_events_reject_bad_last_event_id(make_desk):
    desk, _ = make_desk()
    async with _asgi(_app(desk, _hub("a"))) as http:
        resp = await http.get("/api/events", headers={"last-event-id": "x"})
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})


def test_events_resume_after_last_event_id(make_desk, serve):
    desk, _ = make_desk()
    hub = _hub("a", "b")
    url = serve(_app(desk, hub))
    later = threading.Timer(0.2, lambda: hub.publish(_line("c")))
    later.start()
    with httpx2.Client(timeout=5) as http:
        headers = {"last-event-id": "1"}
        with http.stream("GET", f"{url}/api/events?since=0", headers=headers) as r:
            kind = r.headers["content-type"]
            cache = r.headers["cache-control"]
            frames = _frames(r, lambda fs: fs[-1].get("id") == "3")
    hub.close()
    assert kind.startswith("text/event-stream")
    assert cache == "no-store"
    assert frames[0] == {
        "retry": "1000",
        "event": "hello",
        "data": json.dumps({"epoch": hub.epoch, "last_seq": 2}),
    }
    assert [f["id"] for f in frames[1:]] == ["2", "3"]
    assert frames[2]["data"] == console_line_json(hub.get(3))


def test_events_since_query(make_desk, serve):
    desk, _ = make_desk()
    hub = _hub("a", "b", "c")
    url = serve(_app(desk, hub))
    with httpx2.Client(timeout=5) as http:
        with http.stream("GET", f"{url}/api/events?since=2") as r:
            frames = _frames(r, lambda fs: len(fs) == 2)
    hub.close()
    assert frames[1]["id"] == "3"


def test_events_end_when_hub_closes(make_desk, serve):
    desk, _ = make_desk()
    hub = _hub()
    url = serve(_app(desk, hub))
    threading.Timer(0.2, hub.close).start()
    started = time.monotonic()
    with httpx2.Client(timeout=5) as http:
        with http.stream("GET", f"{url}/api/events") as r:
            frames = _frames(r, lambda fs: False)
    assert len(frames) == 1
    assert time.monotonic() - started < 2


@pytest.mark.anyio
@pytest.mark.parametrize("digits", ["9" * 19, "9" * 5000])
async def test_oversized_numbers_are_rejected(make_desk, digits):
    desk, _ = make_desk()
    bad = {"error": "bad request"}
    # A regression would stream forever through the buffering transport.
    with anyio.fail_after(10):
        async with _asgi(_app(desk, _hub("a"))) as http:
            lines = await http.get("/api/lines", params={"since": digits})
            events = await http.get("/api/events", headers={"last-event-id": digits})
            query = await http.get("/api/events", params={"since": digits})
            gone = await http.get(f"/api/forensic/{digits}")
    assert [(r.status_code, r.json()) for r in (lines, events, query)] == [
        (400, bad)
    ] * 3
    assert (gone.status_code, gone.json()) == (404, {"error": "not found"})
