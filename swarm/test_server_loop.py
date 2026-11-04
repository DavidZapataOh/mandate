import itertools
import threading

import httpx
from starlette.routing import Route

from conftest import DESK_NOW
from gate.certs import generate_keypair
from swarm.conftest import FakeMeta
from swarm.console import AttackRunner, DeployRunner
from swarm.console_line import desk_line
from swarm.hub import EventHub
from swarm.intake import IntentIntake
from swarm.server import build_server
from swarm.test_server import PAIR
from swarm.test_server_intent import BOOK, Ears
from swarm.voice import Transcriber

SIGNED = "A" * 86
HEADERS = {"x-mandate-device-sig": SIGNED, "x-mandate-voice-sig": SIGNED}
PATH_PARAMS = {"{payment_id}": "pay:000001", "{seq}": "1", "{name}": "x"}
BODIES = {"/api/attack": {"kind": "replay"}}
AUDIO = ("/api/voice", "/api/intent/voice")
# The MCP transport runs every tool on a worker thread; static files touch
# no desk.
SKIPPED = ("/mcp", "/app/", "/app/app.js", "/app/app.css", "/app/fonts/{name}")


def _app(desk):
    hub = EventHub()
    nonces = (f"{n:032x}" for n in itertools.count(1))
    gate_priv, _ = generate_keypair()

    def clock():
        return DESK_NOW

    srv = build_server(
        desk,
        PAIR,
        hub=hub,
        attacks=AttackRunner(desk, gate_priv, hub, clock, lambda: next(nonces)),
        deploys=DeployRunner(gate_priv, hub, clock, lambda: next(nonces)),
        voice=Transcriber("vk"),
        intake=IntentIntake(FakeMeta(), BOOK, Ears()),
        agent=FakeMeta(),
    )
    return srv.streamable_http_app(), hub


def _routes(app):
    for route in app.routes:
        if isinstance(route, Route) and route.path not in SKIPPED:
            for method in sorted((route.methods or set()) - {"HEAD"}):
                yield method, route.path


def _send(url, method, path):
    target = path
    for param, value in PATH_PARAMS.items():
        target = target.replace(param, value)
    headers = {"origin": url, **HEADERS}
    query = {"quote": "q:000001"}
    if method == "GET":
        return httpx.get(url + target, params=query, headers=headers, timeout=30)
    if path in AUDIO:
        headers["content-type"] = "audio/wav"
        return httpx.post(
            url + target, params=query, content=b"RIFF", headers=headers, timeout=30
        )
    body = BODIES.get(path, {})
    return httpx.post(url + target, json=body, headers=headers, timeout=30)


def _busy(desk):
    """Hold the desk lock, as a confirm waiting at a slow bank does."""
    release, held = threading.Event(), threading.Event()

    def wait(_bank, _verifier):
        held.set()
        release.wait(30)

    threading.Thread(target=desk.guarded, args=(wait,), daemon=True).start()
    assert held.wait(5)
    return release


def _in_background(fn, *args):
    threading.Thread(target=fn, args=args, daemon=True).start()


def test_no_route_holds_the_event_loop_while_the_desk_is_busy(make_desk, serve):
    stalled = []
    for method, path in _routes(_app(make_desk()[0])[0]):
        desk, _ = make_desk()
        url = serve(_app(desk)[0])
        release = _busy(desk)
        _in_background(_send, url, method, path)
        threading.Event().wait(0.1)
        try:
            httpx.get(f"{url}/api/lines", timeout=1.0)
        except httpx.TimeoutException:
            stalled.append(f"{method} {path}")
        finally:
            release.set()
    assert stalled == []


def test_the_event_stream_keeps_flowing_while_the_desk_is_busy(make_desk, serve):
    desk, _ = make_desk()
    app, hub = _app(desk)
    url = serve(app)
    release = _busy(desk)
    try:
        with httpx.stream("GET", f"{url}/api/events", timeout=1.0) as stream:
            lines = stream.iter_lines()
            assert next(lines) == "retry: 1000"
            _in_background(_send, url, "GET", "/api/keys")
            threading.Event().wait(0.1)
            hub.publish(desk_line("quote", {"status": "denied"}, "while busy"))
            seen = [next(lines) for _ in range(4)]
    finally:
        release.set()
    assert "id: 1" in seen
