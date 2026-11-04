import json

import anyio
import httpx2
import pytest

from swarm import console
from swarm.hub import EventHub
from swarm.server import build_server, split_listeners
from swarm.test_console import CSP, _run_cli
from swarm.test_receipt import GOLDEN
from swarm.test_server import PAIR, _asgi
from swarm.test_server_proofs import HOLDER_COPY, LOCAL_ONLY, _paid

FORWARDED = [
    (b"host", b"desk.example.com"),
    (b"x-forwarded-proto", b"https"),
    (b"x-forwarded-for", b"203.0.113.9"),
]


def _through(trusted, peer):
    """What the app sees of one forwarded request behind uvicorn's middleware."""
    hub = EventHub()
    return _seen_through(
        lambda app: console.console_server(
            app, "127.0.0.1", 8766, hub, trusted=trusted
        ),
        peer,
    )


def _seen_through(build, peer):
    seen = {}

    async def app(scope, receive, send):
        seen.update(scheme=scope["scheme"], client=scope["client"])

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        return None

    built = build(app)
    built.config.load()
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "GET", "scheme": "http", "path": "/", "raw_path": b"/",
        "query_string": b"", "root_path": "", "headers": FORWARDED,
        "client": (peer, 5000), "server": ("127.0.0.1", 8766),
    }  # fmt: skip
    anyio.run(built.config.loaded_app, scope, receive, send)
    return seen["scheme"], seen["client"]


@pytest.mark.parametrize(
    ("trusted", "peer", "want"),
    [
        ((), "127.0.0.1", ("http", ("127.0.0.1", 5000))),
        (("127.0.0.1",), "127.0.0.1", ("https", ("203.0.113.9", 0))),
        (("127.0.0.1",), "198.51.100.7", ("http", ("198.51.100.7", 5000))),
        (("10.0.0.0/8",), "10.1.2.3", ("https", ("203.0.113.9", 0))),
    ],
    ids=["no-proxy-named", "named-proxy", "not-the-proxy", "proxy-network"],
)
def test_forwarded_headers_count_only_from_the_named_proxy(
    monkeypatch, trusted, peer, want
):
    # uvicorn's own default would trust whatever this variable names.
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    assert _through(trusted, peer) == want


PUBLIC_PORT, LOCAL_PORT = 8766, 8767
NOT_FOUND = (404, '{"error":"not found"}')


async def _inner(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"inner"})


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("port", "path", "want"),
    [
        (PUBLIC_PORT, "/mcp", NOT_FOUND),
        (PUBLIC_PORT, "/mcp/", NOT_FOUND),
        (PUBLIC_PORT, "/mcp/messages", NOT_FOUND),
        (PUBLIC_PORT, "/mcpx", (200, "inner")),
        (PUBLIC_PORT, "/api/pending", (200, "inner")),
        (PUBLIC_PORT, "/api/reconcile", NOT_FOUND),
        (PUBLIC_PORT, "/api/anchor", NOT_FOUND),
        (PUBLIC_PORT, "/api/anchors", (200, "inner")),
        (LOCAL_PORT, "/mcp", (200, "inner")),
        (LOCAL_PORT, "/api/pending", (200, "inner")),
        (LOCAL_PORT, "/api/reconcile", (200, "inner")),
        (LOCAL_PORT, "/api/anchor", (200, "inner")),
    ],
    ids=[
        "public-/mcp", "public-/mcp/", "public-/mcp/messages", "public-/mcpx",
        "public-api", "public-reconcile", "public-anchor", "public-anchors",
        "local-/mcp", "local-api", "local-reconcile", "local-anchor",
    ],
)  # fmt: skip
async def test_mcp_answers_only_on_the_local_listener(port, path, want):
    app = split_listeners(_inner, LOCAL_PORT)
    # A loopback Host and no forwarding header: what a Host-rewriting proxy sends.
    async with _asgi(app, f"http://127.0.0.1:{port}") as http:
        resp = await http.post(path)
    assert (resp.status_code, resp.text) == want


def test_split_listeners_pass_the_lifespan_through():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])

    anyio.run(split_listeners(inner, LOCAL_PORT), {"type": "lifespan"}, None, None)
    assert seen == ["lifespan"]


@pytest.mark.anyio
async def test_the_holder_copy_is_served_only_on_the_local_listener(
    make_desk, sign_quote
):
    desk = _paid(make_desk, sign_quote)
    srv = build_server(desk, PAIR, local_port=LOCAL_PORT)
    app = split_listeners(srv.streamable_http_app(), LOCAL_PORT)
    answers = []
    for port in (PUBLIC_PORT, LOCAL_PORT):
        transport = httpx2.ASGITransport(app=app, client=("127.0.0.1", 5000))
        base = f"http://127.0.0.1:{port}"
        async with httpx2.AsyncClient(transport=transport, base_url=base) as http:
            answers.append(await http.get(HOLDER_COPY))
    public, local = answers
    assert (public.status_code, public.json()) == LOCAL_ONLY
    assert local.json() == json.loads(GOLDEN.read_text())


PAGES = ("index.html", "explorer.html", "command.html", "holder.html")


@pytest.fixture
def webapp(tmp_path):
    root = tmp_path / "webapp"
    (root / "fonts").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>copy</title>")
    (root / "app.js").write_text("export {}; // copy")
    (root / "app.css").write_text("body {} /* copy */")
    (root / "fonts" / "inter-latin-400-normal.woff2").write_bytes(b"wOF2 copy")
    return root


@pytest.fixture
def pages(tmp_path):
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    for name in PAGES:
        (root / name).write_text(f"<!doctype html><title>{name}</title>")
    (root / "assets" / "page-a1.js").write_text("export {};")
    return root


@pytest.mark.anyio
async def test_the_web_app_is_served_from_its_named_directory(make_desk, webapp):
    desk, _ = make_desk()
    app = build_server(desk, PAIR, webapp_dir=webapp).streamable_http_app()
    async with _asgi(app) as http:
        page = await http.get("/app/")
        script = await http.get("/app/app.js")
        style = await http.get("/app/app.css")
        font = await http.get("/app/fonts/inter-latin-400-normal.woff2")
        other = await http.get("/app/fonts/other.woff2")
    assert page.text == "<!doctype html><title>copy</title>"
    assert script.text == "export {}; // copy"
    assert style.text == "body {} /* copy */"
    assert font.content == b"wOF2 copy"
    assert other.status_code == 404


@pytest.mark.anyio
async def test_every_page_serves_the_one_policy(make_desk, webapp, pages):
    desk, _ = make_desk()
    srv = build_server(desk, PAIR, console_dir=pages, webapp_dir=webapp)
    paths = ("/console/", *(f"/console/{name}" for name in PAGES), "/app/")
    async with _asgi(srv.streamable_http_app()) as http:
        policies = {
            p: (await http.get(p)).headers.get("content-security-policy") for p in paths
        }
        script = await http.get("/console/assets/page-a1.js")
        app_js = await http.get("/app/app.js")
    assert policies == dict.fromkeys(paths, CSP)
    assert "content-security-policy" not in script.headers
    assert "content-security-policy" not in app_js.headers


def test_a_proxy_network_with_host_bits_is_still_believed(
    monkeypatch, capsys, tmp_path
):
    (tmp_path / "index.html").write_text("<!doctype html><title>Mandate</title>")
    seen, _ = _run_cli(
        monkeypatch, capsys, "--console-dir", str(tmp_path),
        "--trusted-proxy", "10.1.2.3/8",
    )  # fmt: skip
    server = seen["server"]
    assert server.config.forwarded_allow_ips == ["10.0.0.0/8"]

    def build(app):
        server.config.app = app
        return server

    assert _seen_through(build, "10.1.2.3") == ("https", ("203.0.113.9", 0))


@pytest.mark.anyio
@pytest.mark.parametrize(
    "base", [f"http://192.0.2.10:{LOCAL_PORT}", f"http://[2001:db8::1]:{LOCAL_PORT}"]
)
async def test_the_local_port_on_another_interface_is_not_local(base):
    async with _asgi(split_listeners(_inner, LOCAL_PORT), base) as http:
        resp = await http.post("/mcp")
    assert (resp.status_code, resp.text) == NOT_FOUND


@pytest.mark.parametrize(
    ("port", "want"),
    [
        (PUBLIC_PORT, [{"type": "websocket.close", "code": 1000, "reason": ""}]),
        (LOCAL_PORT, [{"type": "websocket.accept"}]),
    ],
    ids=["public", "local"],
)
def test_a_websocket_to_mcp_is_fenced_like_http(port, want):
    sent = []

    async def inner(scope, receive, send):
        await send({"type": "websocket.accept"})

    async def receive():
        return {"type": "websocket.connect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "websocket", "path": "/mcp", "headers": [],
        "server": ("127.0.0.1", port), "client": ("127.0.0.1", 5000),
    }  # fmt: skip
    anyio.run(split_listeners(inner, LOCAL_PORT), scope, receive, send)
    assert sent == want
