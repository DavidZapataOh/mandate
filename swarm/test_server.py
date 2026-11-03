import base64
import json
import re

import httpx2
import pytest
from mcp import Client

from gate.certs import generate_keypair
from swarm import server
from swarm.server import build_server

TOOLS = ["confirm_payment", "get_payment_status", "get_receipt", "quote_payment"]
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
    assert read_only == ["get_payment_status", "get_receipt"]
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
    zero = {"quote_id": "q:000001", "signature": _b64(b"\x00" * 64)}
    good = {"quote_id": "q:000001", "signature": _b64(sign_quote(holder, quoted))}
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
        "quote_id": "q:000001",
        "signature": _b64(sign_quote(holder, quoted)),
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
