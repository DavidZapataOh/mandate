import base64
import json
import re

import anyio
import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import Client

from gate.certs import generate_keypair
from gate.consent import HolderApproval
from swarm import server
from swarm.hub import EventHub
from swarm.server import build_server
from swarm.test_voice import CLIP, RESPONSE, _wav
from swarm.voice import (
    NO_VOICE_KEY,
    VOICE_OFF,
    VOICE_SIG_HEADER,
    Transcriber,
    voice_bytes,
)

TOOLS = [
    "confirm_payment",
    "get_intent",
    "get_payment_status",
    "get_receipt",
    "quote_payment",
]
ARGS = {
    "to_account": "acme-991",
    "amount_cents": 20000,
    "currency": "USD",
    "reference": "A-991",
}
CONFIRM_NOTE = (
    "Executes only after the account holder approves the quote on their own device."
)
PAIR = "pair-0123456789abcdef"
FOREIGN = {"host": "evil.example:8765"}
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'"
)


def _asgi(app, base_url="http://localhost"):
    transport = httpx2.ASGITransport(app=app)
    return httpx2.AsyncClient(transport=transport, base_url=base_url)


def _http(desk):
    return _asgi(build_server(desk, PAIR).streamable_http_app())


def _b64(raw):
    return base64.b64encode(raw).decode()


def _approval_json(quote_id, approval):
    return {
        "quote_id": quote_id,
        "signature": _b64(approval.signature),
        "consent_key": _b64(approval.consent_key),
        "key_signature": _b64(approval.key_signature),
    }


@pytest.mark.anyio
async def test_desk_tools_listed(make_desk):
    desk, _ = make_desk()
    async with Client(build_server(desk, PAIR)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    read_only = sorted(
        name
        for name, tool in tools.items()
        if tool.annotations is not None and tool.annotations.read_only_hint
    )
    assert sorted(tools) == TOOLS
    assert read_only == ["get_intent", "get_payment_status", "get_receipt"]
    assert CONFIRM_NOTE in tools["confirm_payment"].description


@pytest.mark.anyio
async def test_quote_tool_opens_a_quote(make_desk):
    desk, _ = make_desk()
    async with Client(build_server(desk, PAIR)) as client:
        result = await client.call_tool("quote_payment", ARGS)
    body = json.loads(result.content[0].text)
    assert (result.is_error, body["status"], body["quote_id"]) == (
        False,
        "quoted",
        "q:000001",
    )
    assert [q["quote_id"] for q in desk.pending()] == ["q:000001"]


@pytest.mark.anyio
async def test_confirm_tool_without_approval_moves_nothing(make_desk):
    desk, _ = make_desk()
    async with Client(build_server(desk, PAIR)) as client:
        await client.call_tool("quote_payment", ARGS)
        result = await client.call_tool("confirm_payment", {"quote_id": "q:000001"})
    assert json.loads(result.content[0].text)["status"] == "quoted"
    assert desk.bank.get_balance("acme-991") == 0


@pytest.mark.anyio
async def test_pending_and_approve_routes(make_desk, sign_quote):
    desk, holder = make_desk()
    quoted = desk.quote("acme-991", 20000, "USD", "A-991")
    zero = _approval_json(
        "q:000001", HolderApproval(b"\x00" * 64, b"\x00" * 32, b"\x00" * 64)
    )
    good = _approval_json("q:000001", sign_quote(holder, quoted))
    async with _http(desk) as http:
        pending = (await http.get("/api/pending")).json()
        wrong = await http.post("/api/approve", json=zero)
        ok = await http.post("/api/approve", json=good)
    assert [p["quote_id"] for p in pending["pending"]] == ["q:000001"]
    assert (wrong.status_code, wrong.json()["reason"]) == (
        200,
        "consent: bad signature",
    )
    assert (ok.status_code, ok.json()["status"]) == (200, "approved")


@pytest.mark.anyio
@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b'{"quote_id": "q:000001"}',
        b'{"quote_id": "q:000001", "signature": "%%%"}',
        b'{"quote_id": 1, "signature": "AA=="}',
    ],
)
async def test_approve_rejects_bad_requests(make_desk, body):
    desk, _ = make_desk()
    async with _http(desk) as http:
        resp = await http.post("/api/approve", content=body)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
async def test_holder_route_pairs_once(make_desk):
    desk, _ = make_desk(register=False)
    _, first = generate_keypair()
    _, second = generate_keypair()
    async with _http(desk) as http:
        short = await http.post(
            "/api/holder", json={"public_key": _b64(b"x" * 31), "pairing": PAIR}
        )
        a = await http.post(
            "/api/holder", json={"public_key": _b64(first), "pairing": PAIR}
        )
        b = await http.post(
            "/api/holder", json={"public_key": _b64(second), "pairing": PAIR}
        )
    assert short.status_code == 400
    assert a.json() == {"registered": True}
    assert (b.status_code, b.json()) == (400, {"error": "bad request"})
    assert desk.holder_keys == (first,)


@pytest.mark.anyio
@pytest.mark.parametrize("extra", [{}, {"pairing": "wrong"}, {"pairing": 7}])
async def test_holder_route_needs_the_pairing_token(make_desk, extra):
    desk, _ = make_desk(register=False)
    _, key = generate_keypair()
    async with _http(desk) as http:
        resp = await http.post("/api/holder", json={"public_key": _b64(key), **extra})
        ok = await http.post(
            "/api/holder", json={"public_key": _b64(key), "pairing": PAIR}
        )
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})
    assert ok.json() == {"registered": True}


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/holder"),
        ("POST", "/api/approve"),
        ("GET", "/api/pending"),
        ("GET", "/api/device"),
        ("GET", "/app/"),
        ("GET", "/app/app.js"),
    ],
)
async def test_foreign_host_rejected(make_desk, sign_quote, method, path):
    desk, holder = make_desk()
    quoted = desk.quote("acme-991", 20000, "USD", "A-991")
    _, key = generate_keypair()
    body = {
        "public_key": _b64(key),
        "pairing": PAIR,
        **_approval_json("q:000001", sign_quote(holder, quoted)),
    }
    kwargs = {"json": body} if method == "POST" else {}
    async with _http(desk) as http:
        resp = await http.request(method, path, headers=FOREIGN, **kwargs)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})
    assert desk.status("q:000001")["status"] == "quoted"
    assert len(desk.holder_keys) == 1


@pytest.mark.anyio
async def test_allowed_host_with_port_accepted(make_desk):
    desk, _ = make_desk()
    async with _http(desk) as http:
        resp = await http.get("/api/pending", headers={"host": "127.0.0.1:8765"})
    assert resp.status_code == 200


def _run_cli(monkeypatch, capsys, *argv):
    seen = {}
    monkeypatch.setattr(server.uvicorn, "run", lambda app, **kw: seen.update(app=app))
    server.cli(["--port", "18779", *argv])
    pattern = r"Pair the holder device: http://127\.0\.0\.1:18779/app/#pair=(\S+)"
    lines = capsys.readouterr().out.splitlines()
    tokens = [m.group(1) for m in (re.fullmatch(pattern, x) for x in lines) if m]
    return seen["app"], tokens


def test_cli_prints_one_fresh_pairing_url(monkeypatch, capsys):
    _, first = _run_cli(monkeypatch, capsys)
    _, second = _run_cli(monkeypatch, capsys)
    assert len(first) == len(second) == 1
    assert first != second
    assert len(first[0]) >= 16


@pytest.mark.anyio
async def test_cli_app_pairs_with_printed_token(monkeypatch, capsys):
    app, (token,) = _run_cli(monkeypatch, capsys, "--public-host", "desk.example.com")
    _, key = generate_keypair()
    async with _asgi(app, "https://desk.example.com") as http:
        public = await http.get("/api/pending")
        wrong = await http.post(
            "/api/holder", json={"public_key": _b64(key), "pairing": token + "x"}
        )
        ok = await http.post(
            "/api/holder", json={"public_key": _b64(key), "pairing": token}
        )
    assert public.status_code == 200
    assert wrong.status_code == 400
    assert ok.json() == {"registered": True}


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        {"content-type": "text/plain"},
        {"content-type": "application/json", "origin": "https://evil.example"},
    ],
)
async def test_holder_route_rejects_cross_site(make_desk, headers):
    desk, _ = make_desk(register=False)
    _, key = generate_keypair()
    body = json.dumps({"public_key": _b64(key), "pairing": PAIR})
    async with _http(desk) as http:
        resp = await http.post("/api/holder", content=body, headers=headers)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})
    assert desk.holder_keys == ()


@pytest.mark.anyio
async def test_holder_route_accepts_same_origin(make_desk):
    desk, _ = make_desk(register=False)
    _, key = generate_keypair()
    body = json.dumps({"public_key": _b64(key), "pairing": PAIR})
    headers = {
        "content-type": "application/json; charset=utf-8",
        "origin": "http://localhost",
    }
    async with _http(desk) as http:
        resp = await http.post("/api/holder", content=body, headers=headers)
    assert resp.json() == {"registered": True}


@pytest.mark.anyio
async def test_approve_rejects_oversized_body(make_desk):
    desk, _ = make_desk()
    body = {"quote_id": "q" * 5000, "signature": "AA=="}
    async with _http(desk) as http:
        resp = await http.post("/api/approve", json=body)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
@pytest.mark.parametrize("amount", [True, "5"])
async def test_quote_tool_rejects_non_integer_amount(make_desk, amount):
    desk, _ = make_desk()
    async with Client(build_server(desk, PAIR)) as client:
        result = await client.call_tool(
            "quote_payment", {**ARGS, "amount_cents": amount}
        )
    assert result.is_error
    assert desk.pending() == []


@pytest.mark.anyio
async def test_web_app_served_and_nothing_else(make_desk):
    desk, _ = make_desk()
    async with _http(desk) as http:
        page = await http.get("/app/")
        script = await http.get("/app/app.js")
        style = await http.get("/app/app.css")
        suite = await http.get("/app/test_app.mjs")
    assert page.status_code == 200
    assert '<script type="module" src="/app/app.js"></script>' in page.text
    assert CSP in page.text
    assert "<style" not in page.text
    assert style.headers["content-type"].startswith("text/css")
    assert script.headers["content-type"].startswith("text/javascript")
    assert "registerTool" in script.text
    assert suite.status_code == 404


@pytest.mark.anyio
async def test_device_route_reports_the_paired_holder(make_desk):
    desk, _ = make_desk(register=False)
    key = {"public_key": _b64(bytes(range(32))), "pairing": PAIR}
    async with _http(desk) as http:
        before = await http.get("/api/device")
        await http.post("/api/holder", json=key)
        after = await http.get("/api/device")
    assert before.json() == {"paired": False, "fingerprint": None, "voice": False}
    assert after.json() == {
        "paired": True,
        "fingerprint": "630dcd2966c43366",
        "voice": False,
    }


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("voice", "expected"),
    [(None, False), (Transcriber(None), False), (Transcriber("vk"), True)],
    ids=["absent", "no-key", "on"],
)
async def test_device_route_reports_whether_voice_is_on(make_desk, voice, expected):
    desk, _ = make_desk()
    async with _voice_http(desk, voice) as http:
        resp = await http.get("/api/device")
    assert resp.json()["voice"] is expected


WAV = {"content-type": "audio/wav"}
SPOKEN = CLIP.read_bytes()
PERMISSIONS = "microphone=(self), camera=(), geolocation=()"


def _meta(seen, status=200):
    def handler(request):
        seen.append(request)
        body = json.dumps(RESPONSE).encode()
        return httpx2.Response(status, content=body)

    client = httpx2.Client(transport=httpx2.MockTransport(handler))
    return Transcriber("vk", http_client=client)


def _voice_http(desk, voice):
    app = build_server(desk, PAIR, voice=voice).streamable_http_app()
    return _asgi(app)


def _voice_sig(priv, quote, audio):
    raw = Ed25519PrivateKey.from_private_bytes(priv).sign(voice_bytes(quote, audio))
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


async def _speak(http, audio=SPOKEN, quote="q:000001", headers=WAV, sig=None):
    if sig is not None:
        headers = {**headers, VOICE_SIG_HEADER: sig}
    params = {"quote": quote}
    return await http.post("/api/voice", params=params, content=audio, headers=headers)


@pytest.mark.anyio
async def test_voice_route_returns_only_the_transcript(make_desk):
    hub = EventHub()
    desk, holder = make_desk(publish=hub.publish)
    desk.quote("acme-991", 20000, "USD", "A-991")
    before, seen = hub.last_seq, []
    async with _voice_http(desk, _meta(seen)) as http:
        resp = await _speak(http, sig=_voice_sig(holder, "q:000001", SPOKEN))
    sent = seen[0].read()
    heard = {"transcript": RESPONSE["transcript"]}
    assert (resp.status_code, resp.json()) == (200, heard)
    assert SPOKEN in sent
    assert b'"keywords": ["acme-991", "A-991"]' in sent
    assert desk.status("q:000001")["status"] == "quoted"
    assert hub.last_seq == before


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("register", "quote", "headers"),
    [
        (True, "q:000001", {**WAV, **FOREIGN}),
        (True, "q:000001", {"content-type": "application/json"}),
        (True, "q:000001", {**WAV, "origin": "https://evil.example"}),
        (True, "q:000009", WAV),
        (False, "q:000001", WAV),
    ],
    ids=["foreign-host", "not-wav", "foreign-origin", "unknown-quote", "no-holder"],
)
async def test_voice_route_refuses_before_upload(make_desk, register, quote, headers):
    desk, _ = make_desk(register=register)
    desk.quote("acme-991", 20000, "USD", "A-991")
    seen = []
    async with _voice_http(desk, _meta(seen)) as http:
        resp = await _speak(http, quote=quote, headers=headers)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})
    assert seen == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "forge",
    [
        lambda holder, stranger: None,
        lambda holder, stranger: "A" * 85,
        lambda holder, stranger: _voice_sig(stranger, "q:000001", SPOKEN),
        lambda holder, stranger: _voice_sig(holder, "q:000001", SPOKEN + b"\x00"),
        lambda holder, stranger: _voice_sig(holder, "q:000002", SPOKEN),
    ],
    ids=["missing", "malformed", "other-key", "other-audio", "other-quote"],
)
async def test_voice_route_needs_the_paired_device(make_desk, forge):
    desk, holder = make_desk()
    desk.quote("acme-991", 20000, "USD", "A-991")
    desk.quote("acme-991", 20000, "USD", "A-992")
    stranger, _ = generate_keypair()
    seen = []
    async with _voice_http(desk, _meta(seen)) as http:
        resp = await _speak(http, sig=forge(holder, stranger))
    assert (resp.status_code, resp.json()) == (401, {"error": "not the paired device"})
    assert seen == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("audio", "status", "error"),
    [
        (bytes(31_000_001), 413, "audio too large"),
        (_wav(channels=2), 400, "unsupported wav: channels=2"),
    ],
)
async def test_voice_route_refuses_audio_the_service_would(
    make_desk, audio, status, error
):
    desk, holder = make_desk()
    desk.quote("acme-991", 20000, "USD", "A-991")
    seen = []
    sig = _voice_sig(holder, "q:000001", audio)
    async with _voice_http(desk, _meta(seen)) as http:
        resp = await _speak(http, audio=audio, sig=sig)
    assert (resp.status_code, resp.json()) == (status, {"error": error})
    assert seen == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("voice", "reason"), [(None, VOICE_OFF), (Transcriber(None), NO_VOICE_KEY)]
)
async def test_voice_route_without_voice_names_why(make_desk, voice, reason):
    desk, _ = make_desk()
    desk.quote("acme-991", 20000, "USD", "A-991")
    async with _voice_http(desk, voice) as http:
        resp = await _speak(http)
    assert (resp.status_code, resp.json()) == (
        503,
        {"error": "voice unavailable", "reason": reason},
    )


@pytest.mark.anyio
async def test_voice_route_reports_a_failed_transcription(make_desk):
    desk, holder = make_desk()
    desk.quote("acme-991", 20000, "USD", "A-991")
    seen = []
    async with _voice_http(desk, _meta(seen, status=429)) as http:
        resp = await _speak(http, sig=_voice_sig(holder, "q:000001", SPOKEN))
    assert (resp.status_code, resp.json()) == (502, {"error": "model error"})
    assert len(seen) == 1
    assert desk.status("q:000001")["status"] == "quoted"


@pytest.mark.anyio
async def test_holder_page_grants_the_microphone_to_itself_only(make_desk):
    desk, _ = make_desk()
    async with _http(desk) as http:
        page = await http.get("/app/")
    assert page.headers["permissions-policy"] == PERMISSIONS
    assert page.headers["content-security-policy"] == "frame-ancestors 'none'"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("argv", "reason"), [((), VOICE_OFF), (("--voice",), NO_VOICE_KEY)]
)
async def test_cli_voice_is_off_unless_asked(monkeypatch, capsys, argv, reason):
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)
    app, _ = _run_cli(monkeypatch, capsys, *argv)
    async with _asgi(app) as http:
        resp = await _speak(http)
    assert resp.json() == {"error": "voice unavailable", "reason": reason}


@pytest.mark.anyio
async def test_voice_route_hears_a_signed_clip_once(make_desk):
    desk, holder = make_desk()
    desk.quote("acme-991", 20000, "USD", "A-991")
    seen = []
    sig = _voice_sig(holder, "q:000001", SPOKEN)
    async with _voice_http(desk, _meta(seen)) as http:
        first = await _speak(http, sig=sig)
        again = await _speak(http, sig=sig)
    assert first.status_code == 200
    assert (again.status_code, again.json()) == (
        409,
        {"error": "clip already transcribed"},
    )
    assert len(seen) == 1


@pytest.mark.anyio
async def test_voice_route_refuses_a_quote_past_its_deadline(make_desk):
    now = [1800001000]
    desk, holder = make_desk(clock=lambda: now[0])
    desk.quote("acme-991", 20000, "USD", "A-991")
    now[0] += 601
    seen = []

    async def unread():
        raise AssertionError("body read")
        yield b""

    sig = _voice_sig(holder, "q:000001", SPOKEN)
    async with _voice_http(desk, _meta(seen)) as http:
        resp = await _speak(http, audio=unread(), sig=sig)
    assert (resp.status_code, resp.json()) == (409, {"error": "quote expired"})
    assert seen == []


@pytest.mark.anyio
async def test_voice_route_refuses_a_second_upload_before_reading_it(make_desk):
    desk, holder = make_desk()
    desk.quote("acme-991", 20000, "USD", "A-991")
    started, release, seen = anyio.Event(), anyio.Event(), []
    sig = _voice_sig(holder, "q:000001", SPOKEN)

    async def slow():
        started.set()
        await release.wait()
        yield SPOKEN

    async def unread():
        raise AssertionError("body read")
        yield b""

    async with _voice_http(desk, _meta(seen)) as http:
        async with anyio.create_task_group() as tg:
            first = []

            async def go():
                first.append(await _speak(http, audio=slow(), sig=sig))

            tg.start_soon(go)
            await started.wait()
            second = await _speak(http, audio=unread(), sig=sig)
            release.set()
    assert (second.status_code, second.json()) == (409, {"error": "voice busy"})
    assert first[0].status_code == 200
    assert len(seen) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "change",
    [
        {"consent_key": None, "key_signature": None},
        {"key_signature": None},
        {"consent_key": "%%%"},
    ],
)
async def test_approve_needs_the_one_time_key_and_its_certificate(
    make_desk, sign_quote, change
):
    desk, holder = make_desk()
    quoted = desk.quote("acme-991", 20000, "USD", "A-991")
    body = {**_approval_json("q:000001", sign_quote(holder, quoted)), **change}
    sent = {k: v for k, v in body.items() if v is not None}
    async with _http(desk) as http:
        resp = await http.post("/api/approve", json=sent)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})
    assert desk.status("q:000001")["status"] == "quoted"
