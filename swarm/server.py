"""Mandate payment desk served over MCP, with holder approval routes."""

import argparse
import base64
import binascii
import hmac
import json
import secrets
import threading
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any

import uvicorn
from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair
from swarm.desk import PaymentDesk

_MAX_BODY = 4096
_WEBAPP = Path(__file__).resolve().parent.parent / "webapp"
_BAD_REQUEST = {"error": "bad request"}
_DEMO_BALANCE_CENTS = 100000
_LOCAL_HOSTS = ("127.0.0.1", "localhost")
_KEY_LEN = 32


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
) -> MCPServer:
    """Expose a payment desk as MCP tools plus the holder's HTTP routes.

    The tools never approve: only a signature posted to `/api/approve` does.
    The holder key is registered once, by the device that presents the
    pairing token; the token is spent on first use.

    Args:
        desk: Desk the tools and routes operate on.
        pairing_token: One-time secret the holder device posts to `/api/holder`.
        allowed_hosts: Host header names the `/api` and `/app` routes accept.

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
