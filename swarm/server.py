"""Mandate payment desk served over MCP, with holder approval routes."""

import argparse
import base64
import binascii
import hmac
import json
import secrets
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any, Protocol

import anyio
import uvicorn
from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field
from starlette.requests import Request
from starlette.responses import (
    FileResponse,
    JSONResponse,
    Response,
    StreamingResponse,
)

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair
from swarm.console_line import ConsoleLine, console_line_json
from swarm.desk import PaymentDesk
from swarm.hub import EventHub
from swarm.live_attack import (
    ATTACKER_OFF,
    AttackerBusyError,
    AttackerUnavailableError,
    LiveAttacker,
    NoPlanError,
)
from swarm.nimbus import NimbusStep
from swarm.redteam import TEMPLATES, AttackKind

_MAX_BODY = 4096
_WEBAPP = Path(__file__).resolve().parent.parent / "webapp"
_BAD_REQUEST = {"error": "bad request"}
_DEMO_BALANCE_CENTS = 100000
_LOCAL_HOSTS = ("127.0.0.1", "localhost")
_KEY_LEN = 32
_POLL_S = 0.05
_MAX_DIGITS = 18
_HEARTBEAT_S = 15.0
_NOT_FOUND = {"error": "not found"}
_SEND_TIMEOUT_S = 10.0
_CONSOLE_CSP = (
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)
_CONTENT_TYPES = {
    ".html": "text/html",
    ".js": "text/javascript",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".png": "image/png",
    ".woff2": "font/woff2",
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".riv": "application/octet-stream",
    ".wasm": "application/wasm",
}


class AttackSource(Protocol):
    """Anything that can run one template attack and publish its line."""

    def run(self, kind: AttackKind) -> ConsoleLine: ...


class DeploySource(Protocol):
    """Anything that can run one Nimbus step and publish its line."""

    def run(self, step: NimbusStep) -> ConsoleLine: ...


class _BoundedStream(StreamingResponse):
    """Event stream that drops a client which stops reading."""

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        async def bounded(message: Any) -> None:
            with anyio.fail_after(_SEND_TIMEOUT_S):
                await send(message)

        try:
            await super().__call__(scope, receive, bounded)
        except* TimeoutError:
            pass


def _bad_request() -> JSONResponse:
    return JSONResponse(dict(_BAD_REQUEST), status_code=400)


async def _fields(request: Request, *names: str) -> dict[str, Any] | None:
    """Parse a JSON object body and require each named field to be a string."""
    if not _same_site_json(request):
        return None
    raw = await request.body()
    if len(raw) > _MAX_BODY:
        return None
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    if not all(isinstance(body.get(name), str) for name in names):
        return None
    return body


def _same_site_json(request: Request) -> bool:
    # A JSON content type forces a CORS preflight this server never answers, and
    # a present Origin must match, so a foreign page cannot drive these routes.
    kind = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if kind != "application/json":
        return False
    origin = request.headers.get("origin")
    own = f"{request.url.scheme}://{request.url.netloc}"
    return origin is None or origin == own


def _digits(text: str) -> int | None:
    # str.isdigit accepts non-ASCII digits that int() would also parse.
    # The length cap keeps int() away from absurdly long digit strings.
    if len(text) <= _MAX_DIGITS and text.isascii() and text.isdigit():
        return int(text)
    return None


def _since(request: Request) -> int | None:
    """Resume point: `Last-Event-ID` first, then `?since=`, else 0."""
    offered = request.headers.get("last-event-id")
    if offered is None:
        offered = request.query_params.get("since", "0")
    return _digits(offered)


def _hello(hub: EventHub) -> bytes:
    data = json.dumps({"epoch": hub.epoch, "last_seq": hub.last_seq})
    return f"retry: 1000\nevent: hello\ndata: {data}\n\n".encode()


def _frame(line: ConsoleLine) -> bytes:
    return f"id: {line.seq}\ndata: {console_line_json(line)}\n\n".encode()


async def _stream(hub: EventHub, since: int) -> AsyncIterator[bytes]:
    yield _hello(hub)
    last, idle = since, 0.0
    while not hub.closed:
        lines = hub.since(last)
        for line in lines:
            yield _frame(line)
            last = line.seq
        if lines:
            idle = 0.0
            continue
        await anyio.sleep(_POLL_S)
        idle += _POLL_S
        if idle >= _HEARTBEAT_S:
            yield b": keep-alive\n\n"
            idle = 0.0


def _decode(text: str) -> bytes | None:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


class _Pairing:
    """One-time token that lets exactly one device register as the holder."""

    def __init__(self, token: str) -> None:
        self._token: str | None = token
        self._lock = threading.Lock()

    def spend(self, offered: str) -> bool:
        with self._lock:
            if self._token is None or not hmac.compare_digest(
                offered.encode(), self._token.encode()
            ):
                return False
            self._token = None
            return True


def build_server(
    desk: PaymentDesk,
    pairing_token: str,
    allowed_hosts: tuple[str, ...] = _LOCAL_HOSTS,
    hub: EventHub | None = None,
    attacks: AttackSource | None = None,
    console_dir: Path | None = None,
    deploys: DeploySource | None = None,
    live: LiveAttacker | None = None,
) -> MCPServer:
    """Expose a payment desk as MCP tools plus the holder's HTTP routes.

    The tools never approve: only a signature posted to `/api/approve` does.
    The holder key is registered once, by the device that presents the
    pairing token; the token is spent on first use.

    Args:
        desk: Desk the tools and routes operate on.
        pairing_token: One-time secret the holder device posts to `/api/holder`.
        allowed_hosts: Host header names the `/api` and `/app` routes accept.
        hub: When given, also serves its lines on `/api/events` (SSE),
            `/api/lines` and `/api/forensic/{seq}`.
        attacks: When given, also serves `POST /api/attack`.
        console_dir: When given, serves the files found in it at startup under
            `/console/`.
        deploys: When given, POST /api/deploy runs one pinned Nimbus step.
        live: With `attacks`, the open-weights attacker behind
            `POST /api/attack/model`; None reports it as off.

    Returns:
        An MCP server named `mandate`.
    """
    srv = MCPServer("mandate")
    pairing = _Pairing(pairing_token)

    @srv.tool()
    def quote_payment(
        to_account: str,
        amount_cents: Annotated[int, Field(strict=True)],
        currency: str,
        reference: str,
    ) -> dict[str, Any]:
        """Create a quote for a payment. This only creates a quote and moves no money.

        The account holder must approve the quote on their own device before
        confirm_payment can execute it.
        """
        return desk.quote(to_account, amount_cents, currency, reference)

    @srv.tool(annotations=ToolAnnotations(read_only_hint=True))
    def get_payment_status(quote_id: str) -> dict[str, Any]:
        """Return the current state of a quote (quoted, approved, confirmed, denied)."""
        return desk.status(quote_id)

    @srv.tool()
    def confirm_payment(quote_id: str) -> dict[str, Any]:
        """Confirm a quoted payment. Executes only after the account holder approves \
the quote on their own device. Without that approval nothing moves and the quote \
state is returned."""
        return desk.confirm(quote_id)

    @srv.tool(annotations=ToolAnnotations(read_only_hint=True))
    def get_receipt(payment_id: str) -> dict[str, Any]:
        """Return the stored receipt of a confirmed payment."""
        return desk.receipt(payment_id)

    async def pending(request: Request) -> Response:
        return JSONResponse({"pending": desk.pending()})

    async def approve(request: Request) -> Response:
        body = await _fields(request, "quote_id", "signature")
        signature = _decode(body["signature"]) if body else None
        if body is None or signature is None:
            return _bad_request()
        return JSONResponse(desk.approve(body["quote_id"], signature))

    async def holder(request: Request) -> Response:
        body = await _fields(request, "public_key", "pairing")
        key = _decode(body["public_key"]) if body else None
        # Checked before spending so a malformed key does not burn the token.
        if body is None or key is None or len(key) != _KEY_LEN:
            return _bad_request()
        if not pairing.spend(body["pairing"]):
            return _bad_request()
        return JSONResponse({"registered": desk.register_holder(key)})

    async def page(request: Request) -> Response:
        return FileResponse(_WEBAPP / "index.html")

    async def script(request: Request) -> Response:
        return FileResponse(_WEBAPP / "app.js", media_type="text/javascript")

    async def style(request: Request) -> Response:
        return FileResponse(_WEBAPP / "app.css", media_type="text/css")

    async def events(request: Request) -> Response:
        since = _since(request)
        if since is None or hub is None:
            return _bad_request()
        return _BoundedStream(
            _stream(hub, since),
            media_type="text/event-stream; charset=utf-8",
            headers={"cache-control": "no-store"},
        )

    async def lines(request: Request) -> Response:
        since = _digits(request.query_params.get("since", "0"))
        if since is None or hub is None:
            return _bad_request()
        body = "[" + ",".join(console_line_json(x) for x in hub.since(since)) + "]"
        return Response(body, media_type="application/json")

    async def forensic(request: Request) -> Response:
        seq = _digits(request.path_params["seq"])
        found = None if seq is None or hub is None else hub.get(seq)
        if found is None:
            return JSONResponse(dict(_NOT_FOUND), status_code=404)
        return Response(console_line_json(found), media_type="application/json")

    async def attack(request: Request) -> Response:
        body = await _fields(request, "kind")
        try:
            kind = AttackKind(body["kind"]) if body and attacks else None
        except ValueError:
            kind = None
        if kind is None or attacks is None:
            return _bad_request()
        return Response(
            console_line_json(attacks.run(kind)), media_type="application/json"
        )

    async def deploy(request: Request) -> Response:
        body = await _fields(request, "step")
        try:
            step = NimbusStep(body["step"]) if body and deploys else None
        except ValueError:
            step = None
        if step is None or deploys is None:
            return _bad_request()
        return Response(
            console_line_json(deploys.run(step)), media_type="application/json"
        )

    if hub is not None:
        for path, handler in (
            ("/api/events", events),
            ("/api/lines", lines),
            ("/api/forensic/{seq}", forensic),
        ):
            _route(srv, path, "GET", _host_guard(handler, allowed_hosts))
    if attacks is not None:
        _route(srv, "/api/attack", "POST", _host_guard(attack, allowed_hosts))
        _attacker_routes(srv, live, allowed_hosts)
    if deploys is not None:
        _route(srv, "/api/deploy", "POST", _host_guard(deploy, allowed_hosts))
    if console_dir is not None:
        served = _snapshot(console_dir)

        async def console_file(request: Request) -> Response:
            return _console_response(served, request.path_params.get("name", ""))

        for path in ("/console/", "/console/{name:path}"):
            _route(srv, path, "GET", _host_guard(console_file, allowed_hosts))
    for path, method, handler in (
        ("/app/", "GET", page),
        ("/app/app.js", "GET", script),
        ("/app/app.css", "GET", style),
        ("/api/pending", "GET", pending),
        ("/api/approve", "POST", approve),
        ("/api/holder", "POST", holder),
    ):
        _route(srv, path, method, _host_guard(handler, allowed_hosts))
    return srv


def _attacker_routes(
    srv: MCPServer, live: LiveAttacker | None, allowed: tuple[str, ...]
) -> None:
    async def menu(request: Request) -> Response:
        off: dict[str, object] = {
            "available": False,
            "provider": None,
            "model": None,
            "reason": ATTACKER_OFF,
        }
        return JSONResponse(
            {
                "templates": [
                    {"kind": str(kind), "narrative": TEMPLATES[kind].narrative}
                    for kind in AttackKind
                ],
                "attacker": off if live is None else live.status(),
            }
        )

    async def model(request: Request) -> Response:
        body = await _fields(request, "kind")
        try:
            kind = AttackKind(body["kind"]) if body else None
        except ValueError:
            kind = None
        if kind is None:
            return _bad_request()
        if live is None:
            return JSONResponse(
                {"error": "attacker unavailable", "reason": ATTACKER_OFF},
                status_code=503,
            )
        try:
            # A worker thread keeps the loop serving presses and the stream
            # while the provider call blocks.
            line = await anyio.to_thread.run_sync(live.ask, kind)
        except AttackerUnavailableError as err:
            return JSONResponse(
                {"error": "attacker unavailable", "reason": str(err)},
                status_code=503,
            )
        except AttackerBusyError:
            return JSONResponse({"error": "attacker busy"}, status_code=409)
        except NoPlanError as err:
            return JSONResponse(
                {"error": "attacker gave no plan", "detail": str(err)},
                status_code=502,
            )
        return Response(console_line_json(line), media_type="application/json")

    _route(srv, "/api/attack", "GET", _host_guard(menu, allowed))
    _route(srv, "/api/attack/model", "POST", _host_guard(model, allowed))


def _snapshot(root: Path) -> dict[str, Path]:
    root = root.resolve()
    return {
        file.relative_to(root).as_posix(): file
        for file in root.rglob("*")
        if file.is_file() and file.resolve().is_relative_to(root)
    }


def _console_response(served: dict[str, Path], name: str) -> Response:
    file = served.get(name or "index.html")
    if file is None:
        return JSONResponse(dict(_NOT_FOUND), status_code=404)
    kind = _CONTENT_TYPES.get(file.suffix, "application/octet-stream")
    headers = {"cache-control": "no-cache"}
    if file.suffix == ".html":
        headers["content-security-policy"] = _CONSOLE_CSP
    return FileResponse(file, media_type=kind, headers=headers)


_Handler = Callable[[Request], Awaitable[Response]]


def _host_guard(handler: _Handler, allowed: tuple[str, ...]) -> _Handler:
    # A DNS-rebound page reaches this server under its own name; refusing
    # unknown Host values keeps it from driving the holder routes.
    async def guarded(request: Request) -> Response:
        if request.url.hostname not in allowed:
            return _bad_request()
        return await handler(request)

    return guarded


def _route(srv: MCPServer, path: str, method: str, handler: _Handler) -> None:
    # custom_route is unannotated upstream, so mypy rejects it as a decorator.
    srv.custom_route(path, methods=[method])(handler)


def cli(argv: list[str] | None = None) -> None:
    """Console entry point: `mandate-desk [--host H] [--port P] [--source ACCT]`.

    Prints the one-time pairing URL the holder device must open first.
    """
    parser = argparse.ArgumentParser(
        prog="mandate-desk", description="Serve the Mandate payment desk over MCP."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--source", default="checking-881")
    parser.add_argument(
        "--public-host",
        action="append",
        default=[],
        help="extra Host name the holder routes accept, e.g. an HTTPS proxy name",
    )
    args = parser.parse_args(argv)
    token = secrets.token_urlsafe(16)
    gate_key, gate_pub = generate_keypair()
    desk = PaymentDesk(
        source=args.source,
        bank=Bank({args.source: _DEMO_BALANCE_CENTS, "acme-991": 0}),
        verifier=Verifier(gate_pub),
        gate_key=gate_key,
        clock=lambda: int(time.time()),
        nonces=lambda: secrets.token_hex(16),
    )
    allowed = (*_LOCAL_HOSTS, *args.public_host)
    app = build_server(desk, token, allowed).streamable_http_app()
    print(
        f"Pair the holder device: http://{args.host}:{args.port}/app/#pair={token}",
        flush=True,
    )
    uvicorn.run(app, host=args.host, port=args.port)
