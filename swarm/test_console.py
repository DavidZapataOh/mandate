import base64
import itertools
import json
import os
import re
import signal
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from bank.api import Bank
from bank.conftest import SENTINEL_KEY, Cassette, RecordingRail, named_accounts
from bank.credentials import BANK_KEY_ENV, HOLDER_KEY_ENV
from bank.verifier import Verifier
from evidence.conftest import fake_binary
from evidence.zktls import ZKTLS_BIN_ENV
from gate.certs import generate_keypair
from swarm import console
from swarm.conftest import message
from swarm.console import AttackRunner, DeployRunner
from swarm.console_line import ConsoleLine, console_line_json, read_console_line
from swarm.desk import PaymentDesk
from swarm.hub import EventHub
from swarm.nimbus import PINNED as NIMBUS_PINNED
from swarm.nimbus import NimbusStep
from swarm.redteam import PINNED, AttackKind
from swarm.server import build_server
from swarm.test_console_line import RECORD
from swarm.test_server import FOREIGN, PAIR, _asgi
from swarm.test_server_intent import _text
from swarm.test_voice import CLIP
from swarm.voice import NO_VOICE_KEY

CSP = (
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)
NOW = 1800001000


def _world():
    gate_priv, gate_pub = generate_keypair()
    counter = itertools.count(1)
    hub = EventHub()
    desk = PaymentDesk(
        source="checking-881",
        bank=Bank({"checking-881": 50000, "acme-991": 0}),
        verifier=Verifier(gate_pub),
        gate_key=gate_priv,
        clock=lambda: NOW,
        nonces=lambda: f"{next(counter):032x}",
        publish=hub.publish,
    )
    runner = AttackRunner(
        desk, gate_priv, hub, lambda: NOW, lambda: f"atk{next(counter):029d}"
    )
    app = build_server(desk, PAIR, hub=hub, attacks=runner).streamable_http_app()
    return desk, hub, app


@pytest.fixture
def dist(tmp_path):
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>Mandate</title>")
    (root / "assets" / "index-a1.js").write_text("export {};")
    (root / "assets" / "index-a1.css").write_text("body{}")
    (tmp_path / "secret.txt").write_text("nope")
    return root


@pytest.mark.anyio
@pytest.mark.parametrize("kind", list(AttackKind))
async def test_attack_route_publishes_a_blocked_template(kind):
    desk, hub, app = _world()
    async with _asgi(app) as http:
        resp = await http.post("/api/attack", json={"kind": str(kind)})
    line = read_console_line(resp.text)
    assert line == hub.get(1)
    assert (line.subject["layer"], line.subject["reason"]) == PINNED[kind]
    assert (line.subject["blocked"], line.subject["origin"]) == (True, "template")
    assert (line.subject["moved_cents"], line.meta) == (0, None)


@pytest.mark.anyio
async def test_replay_template_pays_once_then_is_refused():
    desk, hub, app = _world()
    async with _asgi(app) as http:
        resp = await http.post("/api/attack", json={"kind": "replay"})
    line = read_console_line(resp.text)
    assert line.subject["reason"] == "replay: jti consumed"
    assert desk.bank.get_balance("acme-991") == 20000
    assert desk.bank.get_balance("checking-881") == 30000
    assert line.forensic["cert_claims"]["action_hash"] == line.forensic["action_hash"]


def test_attacks_pay_from_the_desk_source():
    gate_priv, gate_pub = generate_keypair()
    counter = itertools.count(1)
    hub = EventHub()
    desk = PaymentDesk(
        source="ops-1",
        bank=Bank({"ops-1": 50000, "acme-991": 0}),
        verifier=Verifier(gate_pub),
        gate_key=gate_priv,
        clock=lambda: NOW,
        nonces=lambda: f"{next(counter):032x}",
        publish=hub.publish,
    )
    runner = AttackRunner(
        desk, gate_priv, hub, lambda: NOW, lambda: f"atk{next(counter):029d}"
    )
    line = runner.run(AttackKind.REPLAY)
    assert line.subject["reason"] == "replay: jti consumed"
    assert desk.bank.get_balance("ops-1") == 30000
    assert "checking-881" not in json.dumps(line.forensic)
    assert "ops-1" in json.dumps(line.forensic["cava"])


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("content", "headers"),
    [
        (json.dumps({"kind": "drain_vault"}), {"content-type": "application/json"}),
        (json.dumps({"kind": 1}), {"content-type": "application/json"}),
        (json.dumps({}), {"content-type": "application/json"}),
        (json.dumps({"kind": "replay"}), {"content-type": "text/plain"}),
        (
            json.dumps({"kind": "replay"}),
            {"content-type": "application/json", "origin": "https://evil.example"},
        ),
        (
            json.dumps({"kind": "replay"}),
            {"content-type": "application/json", **FOREIGN},
        ),
    ],
)
async def test_attack_route_rejects_bad_requests(content, headers):
    desk, hub, app = _world()
    async with _asgi(app) as http:
        resp = await http.post("/api/attack", content=content, headers=headers)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})
    assert hub.last_seq == 0
    assert desk.bank.get_balance("acme-991") == 0


@pytest.mark.anyio
async def test_attack_route_absent_without_runner(make_desk):
    desk, _ = make_desk()
    app = build_server(desk, PAIR, hub=EventHub()).streamable_http_app()
    async with _asgi(app) as http:
        resp = await http.post("/api/attack", json={"kind": "replay"})
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_console_serves_exact_build_files(make_desk, dist):
    desk, _ = make_desk()
    app = build_server(desk, PAIR, console_dir=dist).streamable_http_app()
    async with _asgi(app) as http:
        page = await http.get("/console/")
        named = await http.get("/console/index.html")
        script = await http.get("/console/assets/index-a1.js")
        style = await http.get("/console/assets/index-a1.css")
        missing = await http.get("/console/assets/other.js")
        escape = await http.get("/console/%2e%2e/secret.txt")
        foreign = await http.get("/console/", headers=FOREIGN)
    assert (page.status_code, page.text) == (200, named.text)
    assert page.headers["content-type"].startswith("text/html")
    assert page.headers["content-security-policy"] == CSP
    assert script.headers["content-type"].startswith("text/javascript")
    assert "content-security-policy" not in script.headers
    assert style.headers["content-type"].startswith("text/css")
    assert (missing.status_code, missing.json()) == (404, {"error": "not found"})
    assert escape.status_code == 404
    assert foreign.status_code == 400


@pytest.mark.anyio
async def test_console_skips_links_that_leave_the_build(make_desk, dist):
    (dist / "assets" / "outside.txt").symlink_to(dist.parent / "secret.txt")
    (dist / "assets" / "inside.js").symlink_to(dist / "assets" / "index-a1.js")
    desk, _ = make_desk()
    app = build_server(desk, PAIR, console_dir=dist).streamable_http_app()
    async with _asgi(app) as http:
        outside = await http.get("/console/assets/outside.txt")
        inside = await http.get("/console/assets/inside.js")
        normal = await http.get("/console/assets/index-a1.js")
    assert (outside.status_code, outside.json()) == (404, {"error": "not found"})
    assert (inside.status_code, normal.status_code) == (200, 200)


def _run_cli(monkeypatch, capsys, *argv):
    seen = {}

    def run(self, sockets=None):
        seen.update(app=self.config.app, hub=self._hub)

    monkeypatch.setattr(console._ConsoleServer, "run", run)
    console.cli(["--port", "18780", *argv])
    return seen, capsys.readouterr().out.splitlines()


@pytest.mark.anyio
async def test_cli_serves_desk_console_and_attacks(monkeypatch, capsys, dist):
    seen, out = _run_cli(monkeypatch, capsys, "--console-dir", str(dist))
    pair = r"Pair the holder device: http://127\.0\.0\.1:18780/app/#pair=\S{16,}"
    assert re.fullmatch(pair, out[0])
    assert out[1] == "Console: http://127.0.0.1:18780/console/"
    async with _asgi(seen["app"]) as http:
        page = await http.get("/console/")
        attack = await http.post("/api/attack", json={"kind": "payee_swap"})
        lines = await http.get("/api/lines")
    assert page.status_code == 200
    assert read_console_line(attack.text).subject["blocked"] is True
    assert [item["seq"] for item in lines.json()] == [1]


def test_cli_refuses_a_missing_build(monkeypatch, capsys, tmp_path):
    with pytest.raises(SystemExit) as stopped:
        _run_cli(monkeypatch, capsys, "--console-dir", str(tmp_path))
    assert stopped.value.code == 2
    assert "console build missing" in capsys.readouterr().err


@pytest.mark.anyio
async def test_cli_records_every_line(monkeypatch, capsys, dist, tmp_path):
    path = tmp_path / "run.jsonl"
    seen, _ = _run_cli(
        monkeypatch, capsys, "--console-dir", str(dist), "--record", str(path)
    )
    async with _asgi(seen["app"]) as http:
        await http.post("/api/attack", json={"kind": "mcp_exfil"})
    seen["hub"].close()
    assert path.read_text() == console_line_json(seen["hub"].get(1)) + "\n"


def test_cli_follows_the_hook_journal(monkeypatch, capsys, dist, tmp_path):
    journal = tmp_path / "journal.jsonl"
    journal.write_text(json.dumps(RECORD) + "\n")
    seen, _ = _run_cli(
        monkeypatch, capsys, "--console-dir", str(dist), "--journal", str(journal)
    )
    hub = seen["hub"]
    deadline = time.monotonic() + 5
    while hub.last_seq < 1 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert hub.get(1).source == "hook"


def test_exit_signal_closes_the_hub():
    hub = EventHub()
    server = console._ConsoleServer(uvicorn.Config(lambda *a: None), hub)
    server.handle_exit(signal.SIGINT, None)
    assert (hub.closed, server.should_exit) == (True, True)


def test_shutdown_is_bounded_with_a_client_that_never_reads(make_desk):
    desk, _ = make_desk()
    hub = EventHub()
    app = build_server(desk, PAIR, hub=hub).streamable_http_app()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = console.console_server(app, "127.0.0.1", port, hub)
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, daemon=True
    )
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    stalled = socket.socket()
    stalled.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    stalled.settimeout(5)
    stalled.connect(("127.0.0.1", port))
    stalled.sendall(b"GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    big = "x" * 200_000
    subject = {"agent": big, "tool": "t", "targets": [], "tool_use_id": None}
    try:
        for _ in range(100):
            hub.publish(ConsoleLine(0, "hook", None, None, subject, None))
        time.sleep(0.5)
        server.handle_exit(signal.SIGINT, None)
        thread.join(5)
        assert not thread.is_alive()
    finally:
        server.should_exit = True
        stalled.close()


def _nimbus(make_desk):
    desk, _ = make_desk()
    gate_priv, _ = generate_keypair()
    counter = itertools.count(1)
    hub = EventHub()
    runner = DeployRunner(
        gate_priv, hub, lambda: NOW, lambda: f"dep{next(counter):029d}"
    )
    app = build_server(desk, PAIR, hub=hub, deploys=runner).streamable_http_app()
    return hub, app


@pytest.mark.anyio
@pytest.mark.parametrize("step", list(NimbusStep))
async def test_deploy_route_publishes_each_step(make_desk, step):
    hub, app = _nimbus(make_desk)
    async with _asgi(app) as http:
        resp = await http.post("/api/deploy", json={"step": str(step)})
    line = read_console_line(resp.text)
    assert line == hub.get(1)
    assert (line.source, line.subject["step"]) == ("deploy", str(step))
    assert (line.subject["layer"], line.subject["reason"]) == NIMBUS_PINNED[step]
    assert line.subject["blocked"] is (step is not NimbusStep.RELEASE)


@pytest.mark.anyio
async def test_every_release_click_is_certified_anew(make_desk):
    hub, app = _nimbus(make_desk)
    async with _asgi(app) as http:
        for _ in range(2):
            await http.post("/api/deploy", json={"step": "release"})
    first, second = hub.get(1), hub.get(2)
    assert [first.subject["reason"], second.subject["reason"]] == [
        "ok: released",
        "ok: released",
    ]
    assert first.event["cert"] != second.event["cert"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("content", "headers"),
    [
        (json.dumps({"step": "drop_db"}), {"content-type": "application/json"}),
        (json.dumps({"step": 1}), {"content-type": "application/json"}),
        (json.dumps({}), {"content-type": "application/json"}),
        (json.dumps({"step": "release"}), {"content-type": "text/plain"}),
        (
            json.dumps({"step": "release"}),
            {"content-type": "application/json", "origin": "https://evil.example"},
        ),
        (
            json.dumps({"step": "release"}),
            {"content-type": "application/json", **FOREIGN},
        ),
    ],
)
async def test_deploy_route_rejects_bad_requests(make_desk, content, headers):
    hub, app = _nimbus(make_desk)
    async with _asgi(app) as http:
        resp = await http.post("/api/deploy", content=content, headers=headers)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})
    assert hub.last_seq == 0


@pytest.mark.anyio
async def test_deploy_route_absent_without_runner(make_desk):
    desk, _ = make_desk()
    app = build_server(desk, PAIR, hub=EventHub()).streamable_http_app()
    async with _asgi(app) as http:
        resp = await http.post("/api/deploy", json={"step": "release"})
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_cli_serves_the_nimbus_steps(monkeypatch, capsys, dist):
    seen, _ = _run_cli(monkeypatch, capsys, "--console-dir", str(dist))
    async with _asgi(seen["app"]) as http:
        resp = await http.post("/api/deploy", json={"step": "stale_migration"})
    line = read_console_line(resp.text)
    assert (line.seq, line.subject["reason"]) == (1, "no rule matches")


@pytest.mark.anyio
async def test_cli_wires_voice_when_asked(monkeypatch, capsys, dist):
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)
    seen, _ = _run_cli(monkeypatch, capsys, "--console-dir", str(dist), "--voice")
    async with _asgi(seen["app"]) as http:
        resp = await http.post(
            "/api/voice",
            params={"quote": "q:000001"},
            content=CLIP.read_bytes(),
            headers={"content-type": "audio/wav"},
        )
    assert resp.json() == {"error": "voice unavailable", "reason": NO_VOICE_KEY}


ATTACK_HASH = "89f0357807b9d6e90a1c66d00e2a058ad97a5370349978a0ddceb67c50653f9a"


def _runner(salts=None):
    gate_priv, gate_pub = generate_keypair()
    hub = EventHub()
    desk = PaymentDesk(
        source="checking-881",
        bank=Bank({"checking-881": 50000, "acme-991": 0}),
        verifier=Verifier(gate_pub),
        gate_key=gate_priv,
        clock=lambda: NOW,
        nonces=lambda: "0" * 32,
        publish=hub.publish,
    )
    nonce = "atk00000000000000000000000000003"
    return AttackRunner(desk, gate_priv, hub, lambda: NOW, lambda: nonce, salts)


def test_counted_salts_reproduce_the_golden_attack_hash():
    line = _runner(lambda: b"\xa3" * 32).run(AttackKind.PAYEE_SWAP)
    assert line.event["action"] == line.forensic["action_hash"] == ATTACK_HASH


def test_presses_without_given_salts_never_repeat_a_hash():
    runner = _runner()
    first, second = (runner.run(AttackKind.PAYEE_SWAP) for _ in range(2))
    assert first.forensic["cava"] == second.forensic["cava"]
    assert first.event["action"] != second.event["action"]


DEPLOY_HASH = "1be9ccd395f38aeb073d15560b4bdc8bc07326b8457578c8d5db799b92ccaa01"


def test_counted_salts_reproduce_the_golden_deploy_hash():
    gate_priv, _ = generate_keypair()
    nonce = "dep00000000000000000000000000009"
    runner = DeployRunner(
        gate_priv, EventHub(), lambda: NOW, lambda: nonce, lambda: b"\xd9" * 32
    )
    line = runner.run(NimbusStep.RELEASE)
    assert line.event["action"] == line.forensic["action_hash"] == DEPLOY_HASH
    assert line.forensic["cert_claims"]["action_hash"] == DEPLOY_HASH


def test_public_host_help_says_the_console_routes_publish_payments(monkeypatch, capsys):
    monkeypatch.setenv("COLUMNS", "400")
    with pytest.raises(SystemExit):
        console.cli(["--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert (
        "the console routes (/api/lines, /api/events, /api/forensic) show every "
        "payment's amount, payee, reference and debit account in clear to anyone "
        "who reaches that name: use a public host for demo data only"
    ) in text


@pytest.mark.anyio
async def test_cli_without_a_key_has_no_spark(monkeypatch, capsys, dist):
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)
    seen, _ = _run_cli(monkeypatch, capsys, "--console-dir", str(dist))
    async with _asgi(seen["app"]) as http:
        draft = await http.post("/api/intent/draft", json={"text": "Pay Acme."})
        agent = await http.get("/api/agent")
    assert draft.status_code == agent.status_code == 503


@pytest.mark.anyio
async def test_cli_drafts_with_the_meta_key(monkeypatch, capsys, dist, fake_meta):
    monkeypatch.setenv("MODEL_API_KEY", "mk-test")
    made = []
    draft = {
        "payee_name": "Acme Corp",
        "amount_cents": 20000,
        "currency": "USD",
        "reference": "A991",
    }

    def client(key):
        made.append(key)
        return fake_meta([message(json.dumps(draft))])

    monkeypatch.setattr(console, "MetaClient", client)
    seen, out = _run_cli(monkeypatch, capsys, "--console-dir", str(dist))
    token = out[0].rsplit("#pair=", 1)[1]
    device_priv, device_pub = generate_keypair()
    async with _asgi(seen["app"]) as http:
        await http.post(
            "/api/holder",
            json={
                "public_key": base64.b64encode(device_pub).decode(),
                "pairing": token,
            },
        )
        resp = await http.post(
            "/api/intent/draft", **_text("Pay Acme A991.", device_priv)
        )
        start = await http.post("/api/agent/start", json={"intent_id": "i:000001"})
    assert made == ["mk-test"]
    assert (start.status_code, start.json()) == (
        401,
        {"error": "not the paired device"},
    )
    assert resp.json()["intent"] == {
        "amount_cents": 20000,
        "currency": "USD",
        "recipient": "acme-991",
        "reference": "A-991",
    }


def test_cli_refuses_a_bad_payee_book(monkeypatch, capsys, dist, tmp_path):
    book = tmp_path / "payees.json"
    book.write_text("[]")
    with pytest.raises(SystemExit) as stopped:
        _run_cli(monkeypatch, capsys, "--console-dir", str(dist), "--payees", str(book))
    assert stopped.value.code == 2
    assert f"payee book unreadable: {book}" in capsys.readouterr().err


def test_attacks_need_a_simulated_bank_beside_a_sandbox_desk():
    gate_priv, gate_pub = generate_keypair()
    rail = RecordingRail()
    desk = PaymentDesk(
        source="checking-881",
        bank=rail,
        verifier=Verifier(gate_pub),
        gate_key=gate_priv,
        clock=lambda: NOW,
        nonces=lambda: "d" * 32,
    )
    with pytest.raises(ValueError, match="template attacks need a simulated bank"):
        AttackRunner(desk, gate_priv, EventHub(), lambda: NOW, lambda: "a" * 32)
    counter = itertools.count(1)
    sim = Bank({"checking-881": 10_000_000, "acme-991": 0})
    runner = AttackRunner(
        desk,
        gate_priv,
        EventHub(),
        lambda: NOW,
        lambda: f"atk{next(counter):029d}",
        bank=sim,
    )
    line = runner.run(AttackKind.REPLAY)
    assert line.subject["blocked"] is True
    assert sim.get_balance("acme-991") == 20000
    assert rail.calls == []


def test_cli_sandbox_rail_needs_the_key(monkeypatch, capsys, dist):
    monkeypatch.delenv(BANK_KEY_ENV, raising=False)
    with pytest.raises(SystemExit) as stopped:
        _run_cli(monkeypatch, capsys, "--console-dir", str(dist), "--rail", "sandbox")
    assert stopped.value.code == 2
    assert capsys.readouterr().err == (
        "bank rail unavailable: set INCREASE_SANDBOX_API_KEY\n"
    )


def test_cli_sandbox_rail_needs_the_demo_accounts(monkeypatch, capsys, dist):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    cassette = Cassette("accounts_list")
    monkeypatch.setattr(console, "sandbox_client", lambda key: cassette.client())
    with pytest.raises(SystemExit) as stopped:
        _run_cli(monkeypatch, capsys, "--console-dir", str(dist), "--rail", "sandbox")
    assert stopped.value.code == 2
    assert capsys.readouterr().err == "bank accounts missing: run mandate-bank-setup\n"


@pytest.mark.parametrize(
    "refusal",
    [
        (401, {"type": "invalid_api_key_error", "status": 401}),
        (403, {"type": "environment_mismatch_error", "status": 403}),
    ],
)
def test_cli_sandbox_rail_refused_key(monkeypatch, capsys, dist, refusal):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    cassette = Cassette(refusal)
    monkeypatch.setattr(console, "sandbox_client", lambda key: cassette.client())
    with pytest.raises(SystemExit) as stopped:
        _run_cli(monkeypatch, capsys, "--console-dir", str(dist), "--rail", "sandbox")
    assert stopped.value.code == 2
    err = capsys.readouterr().err
    assert err == "bank rail unavailable: the sandbox refused the key\n"
    assert BANK_KEY_ENV not in os.environ


@pytest.mark.parametrize(
    "failure", [httpx.ConnectError("down"), httpx.ReadTimeout("slow")]
)
def test_cli_sandbox_rail_unreachable(monkeypatch, capsys, dist, failure):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    cassette = Cassette(failure)
    monkeypatch.setattr(console, "sandbox_client", lambda key: cassette.client())
    with pytest.raises(SystemExit) as stopped:
        _run_cli(monkeypatch, capsys, "--console-dir", str(dist), "--rail", "sandbox")
    assert stopped.value.code == 2
    err = capsys.readouterr().err
    assert err == "bank rail unavailable: the sandbox is unreachable\n"


@pytest.mark.anyio
async def test_cli_sandbox_console_keeps_attacks_simulated(monkeypatch, capsys, dist):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    keys = []
    cassette = Cassette(named_accounts("checking-881", "acme-991"))

    def client(key):
        keys.append(key)
        return cassette.client()

    monkeypatch.setattr(console, "sandbox_client", client)
    seen, _ = _run_cli(
        monkeypatch, capsys, "--console-dir", str(dist), "--rail", "sandbox"
    )
    assert keys == [SENTINEL_KEY]
    assert BANK_KEY_ENV not in os.environ
    async with _asgi(seen["app"]) as http:
        attack = await http.post("/api/attack", json={"kind": "replay"})
    bank = read_console_line(attack.text).forensic["bank"]
    assert (bank["rail"], bank["transfer_id"]) == ("simulated", "pay:000001")
    assert [r.url.path for r in cassette.requests] == ["/accounts"]


def test_cli_drops_the_holder_key(monkeypatch, capsys, dist):
    monkeypatch.setenv(HOLDER_KEY_ENV, "holder_key_SENTINEL_51c2")
    _run_cli(monkeypatch, capsys, "--console-dir", str(dist))
    assert HOLDER_KEY_ENV not in os.environ


FAKE_NOTARY = (
    "import json, sys, time\n"
    "from cryptography.hazmat.primitives import serialization as s\n"
    "from cryptography.hazmat.primitives.asymmetric import ec\n"
    "path = sys.argv[sys.argv.index('--key-file') + 1]\n"
    "k = ec.derive_private_key(int(open(path).read(), 16), ec.SECP256K1())\n"
    "pub = k.public_key().public_bytes(\n"
    "    s.Encoding.X962, s.PublicFormat.CompressedPoint)\n"
    "print(json.dumps({'listening': sys.argv[3], 'notary_key': pub.hex()}),\n"
    "      flush=True)\n"
    "time.sleep(30)"
)


def _sandbox(monkeypatch):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    cassette = Cassette(named_accounts("checking-881", "acme-991"))
    monkeypatch.setattr(console, "sandbox_client", lambda key: cassette.client())


def test_cli_zktls_needs_the_sandbox_rail(monkeypatch, capsys, dist):
    with pytest.raises(SystemExit) as stopped:
        _run_cli(monkeypatch, capsys, "--console-dir", str(dist), "--zktls")
    assert stopped.value.code == 2
    assert capsys.readouterr().err == "zktls needs --rail sandbox\n"


def test_cli_zktls_needs_the_binary(monkeypatch, capsys, dist):
    _sandbox(monkeypatch)
    monkeypatch.delenv(ZKTLS_BIN_ENV, raising=False)
    with pytest.raises(SystemExit) as stopped:
        _run_cli(
            monkeypatch, capsys, "--console-dir", str(dist), "--rail", "sandbox",
            "--zktls",
        )  # fmt: skip
    assert stopped.value.code == 2
    assert capsys.readouterr().err == (
        "zktls unavailable: set MANDATE_ZKTLS_BIN to a built mandate-zktls\n"
    )


@pytest.mark.anyio
async def test_cli_sandbox_zktls_wires_the_notary(monkeypatch, capsys, dist, tmp_path):
    _sandbox(monkeypatch)
    monkeypatch.setenv(ZKTLS_BIN_ENV, fake_binary(tmp_path, FAKE_NOTARY))
    seen, _ = _run_cli(
        monkeypatch, capsys, "--console-dir", str(dist), "--rail", "sandbox",
        "--zktls",
    )  # fmt: skip
    async with _asgi(seen["app"]) as http:
        answer = await http.post(
            "/api/intent/funds-challenge", json={"intent_id": "i:000009"}
        )
    assert answer.json() == {"status": "unknown", "intent_id": "i:000009"}


def test_cli_zktls_refuses_a_busy_notary_port(monkeypatch, capsys, dist, tmp_path):
    _sandbox(monkeypatch)
    monkeypatch.setenv(ZKTLS_BIN_ENV, fake_binary(tmp_path, FAKE_NOTARY))
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        held.listen()
        busy = f"127.0.0.1:{held.getsockname()[1]}"
        monkeypatch.setattr(console, "NOTARY_LISTEN", busy)
        with pytest.raises(SystemExit) as stopped:
            _run_cli(
                monkeypatch, capsys, "--console-dir", str(dist), "--rail", "sandbox",
                "--zktls",
            )  # fmt: skip
    assert stopped.value.code == 2
    assert capsys.readouterr().err == (
        f"zktls unavailable: notary: {busy} is already in use\n"
    )
