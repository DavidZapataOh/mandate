"""Mandate payment desk served over MCP, with holder approval routes."""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, Protocol

import anyio
import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
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
from gate.consent import HolderApproval
from gate.policy import Intent
from swarm.agent import Responder
from swarm.console_line import ConsoleLine, console_line_json
from swarm.desk import PaymentDesk
from swarm.handoff import AgentHandoff
from swarm.hub import EventHub
from swarm.intake import IntentIntake
from swarm.live_attack import (
    ATTACKER_OFF,
    AttackerBusyError,
    AttackerUnavailableError,
    LiveAttacker,
    NoPlanError,
)
from swarm.meta_client import MetaAPIError
from swarm.nimbus import NimbusStep
from swarm.provenance import provenance
from swarm.receipt import present
from swarm.redteam import TEMPLATES, AttackKind
from swarm.voice import (
    MAX_WAV_BYTES,
    VOICE_OFF,
    VOICE_SIG_HEADER,
    Transcriber,
    VoiceAPIError,
    VoiceBusyError,
    transcriber_from_env,
    verify_voice,
)

_MAX_BODY = 4096
_MAX_TEXT = 500
_DEVICE_SIG_HEADER = "x-mandate-device-sig"
_DRAFT_DOMAIN = "mandate/intent-draft/v1"
_VOICE_DOMAIN = "mandate/intent-voice/v1"
_AGENT_DOMAIN = "mandate/agent-start/v1"
_INTENT_KEYS = frozenset({"amount_cents", "currency", "recipient", "reference"})
_WEBAPP = Path(__file__).resolve().parent.parent / "webapp"
_BAD_REQUEST = {"error": "bad request"}
_APPROVAL = ("signature", "consent_key", "key_signature")
_DEMO_BALANCE_CENTS = 100000
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
_LOOPBACK_CLIENTS = frozenset({"127.0.0.1", "::1", "::ffff:127.0.0.1"})
# Any of these means a proxy relayed the request, so its loopback peer
# address says nothing about who asked.
_PROXY_HEADERS = (
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "cf-connecting-ip",
)
_KEY_LEN = 32
_POLL_S = 0.05
_MAX_DIGITS = 18
_HEARTBEAT_S = 15.0
_NOT_FOUND = {"error": "not found"}
_SEND_TIMEOUT_S = 10.0
_NOT_PAIRED_DEVICE = {"error": "not the paired device"}
_VOICE_SIG = re.compile(r"[A-Za-z0-9_-]{86}")
_PAGE_HEADERS = {
    "permissions-policy": "microphone=(self), camera=(), geolocation=()",
    # A meta CSP cannot carry frame-ancestors; without it a foreign page could
    # frame the holder page and overlay its Approve button.
    "content-security-policy": "frame-ancestors 'none'",
}
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


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _bad_request() -> JSONResponse:
    return JSONResponse(dict(_BAD_REQUEST), status_code=400)


async def _fields(request: Request, *names: str) -> dict[str, Any] | None:
    """Parse a JSON object body and require each named field to be a string."""
    if not _same_site(request, "application/json"):
        return None
    raw = await request.body()
    if len(raw) > _MAX_BODY:
        return None
    return _parse_fields(raw, names)


def _parse_fields(raw: bytes, names: tuple[str, ...]) -> dict[str, Any] | None:
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    if not all(isinstance(body.get(name), str) for name in names):
        return None
    return body


def _same_site(request: Request, content_type: str) -> bool:
    # A non-simple content type, JSON or WAV, forces a CORS preflight this server
    # never answers, and a present Origin must match, so a foreign page cannot
    # drive these routes.
    kind = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if kind != content_type:
        return False
    origin = request.headers.get("origin")
    own = f"{request.url.scheme}://{request.url.netloc}"
    return origin is None or origin == own


async def _capped_body(request: Request, limit: int) -> bytes | None:
    """Read the body, or None as soon as it grows past `limit` bytes."""
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return bytes(body)


def _intent_of(raw: Any) -> Intent | None:
    """The intent a request carries: exactly four keys of the right types."""
    if not isinstance(raw, dict) or raw.keys() != _INTENT_KEYS:
        return None
    amount, currency, recipient, reference = (raw[k] for k in sorted(_INTENT_KEYS))
    texts = (currency, recipient, reference)
    if type(amount) is not int or not all(isinstance(t, str) for t in texts):
        return None
    return Intent(amount, currency, recipient, reference)


@contextmanager
def _one_at_a_time(flags: dict[str, bool], name: str) -> Iterator[bool]:
    """Claim a route's single slot before its body is read.

    The loop is single-threaded and nothing awaits between the check and the
    claim, so parallel uploads cannot each buffer a full body.
    """
    if flags[name]:
        yield False
        return
    flags[name] = True
    try:
        yield True
    finally:
        flags[name] = False


def _draft_busy() -> JSONResponse:
    return JSONResponse({"error": "draft busy"}, status_code=409)


def _device_proved(
    request: Request, domain: str, body: bytes, desk: PaymentDesk
) -> bool:
    """True when a paired holder key signed the exact body received.

    The signature authenticates the uploading device before any model call.
    Its domain differs per route and from consent and voice signatures.
    """
    offered = request.headers.get(_DEVICE_SIG_HEADER)
    if offered is None or not _VOICE_SIG.fullmatch(offered):
        return False
    signature = base64.urlsafe_b64decode(offered + "==")
    digest = hashlib.sha256(body).hexdigest()
    message = f"{domain}\n{digest}".encode()
    for key in desk.holder_keys:
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        except (InvalidSignature, ValueError):
            continue
        return True
    return False


def _model_off() -> JSONResponse:
    return JSONResponse({"error": "model unavailable"}, status_code=503)


async def _draft(draft: Callable[[Any], dict[str, Any]], words: Any) -> Response:
    # A worker thread keeps the loop serving while the model call blocks.
    try:
        return JSONResponse(await anyio.to_thread.run_sync(draft, words))
    except ValueError as err:
        return JSONResponse({"error": str(err)}, status_code=400)
    except (MetaAPIError, VoiceAPIError):
        return JSONResponse({"error": "model error"}, status_code=502)


def _voice_signature(request: Request) -> bytes | None:
    offered = request.headers.get(VOICE_SIG_HEADER)
    if offered is None or not _VOICE_SIG.fullmatch(offered):
        return None
    return base64.urlsafe_b64decode(offered + "==")


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


def _approval(body: dict[str, Any]) -> HolderApproval | None:
    """Decode the one-time signature, its key and the holder's certificate."""
    signature, consent_key, key_signature = (_decode(body[n]) for n in _APPROVAL)
    if signature is None or consent_key is None or key_signature is None:
        return None
    return HolderApproval(signature, consent_key, key_signature)


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
    voice: Transcriber | None = None,
    intake: IntentIntake | None = None,
    agent: Responder | None = None,
) -> MCPServer:
    """Expose a payment desk as MCP tools plus the holder's HTTP routes.

    The tools never approve: only a holder approval posted to `/api/approve`
    does.
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
        voice: Transcriber behind `POST /api/voice`, which answers only the
            words of a clip the paired device signed; None reports it as off.
        intake: When given, drafts intents from typed or spoken words behind
            `POST /api/intent/draft` and `/api/intent/voice`; None reports
            drafting as unavailable.
        agent: When given, Muse Spark pays a signed intent handed to it behind
            `POST /api/agent/start` and `GET /api/agent`; None reports both as
            unavailable.

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
        intent_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a quote for a payment. This only creates a quote and moves no money.

        The account holder must approve the quote on their own device before
        confirm_payment can execute it. Name the holder's signed intent_id when \
there is one: the gate then pays only a quote that matches it exactly.
        """
        return desk.quote(to_account, amount_cents, currency, reference, intent_id)

    @srv.tool(annotations=ToolAnnotations(read_only_hint=True))
    def get_intent(intent_id: str) -> dict[str, Any]:
        """Return the payment the account holder signed: amount, currency, payee \
account, invoice reference, and its hash and evidence reference."""
        return desk.intent_receipt(intent_id)

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
        body = await _fields(request, "quote_id", *_APPROVAL)
        approval = _approval(body) if body else None
        if body is None or approval is None:
            return _bad_request()
        return JSONResponse(desk.approve(body["quote_id"], approval))

    async def sign_intent(request: Request) -> Response:
        body = await _fields(request, "signature")
        intent = _intent_of(body.get("intent")) if body else None
        signature = _decode(body["signature"]) if body else None
        if intent is None or signature is None:
            return _bad_request()
        return JSONResponse(desk.record_intent(intent, signature))

    handoff = None if agent is None else AgentHandoff(agent, srv, desk)

    async def agent_start(request: Request) -> Response:
        if handoff is None:
            return _model_off()
        if not _same_site(request, "application/json"):
            return _bad_request()
        raw = await _capped_body(request, _MAX_BODY)
        if raw is None:
            return _bad_request()
        # The run spends model calls, so the paired device must ask for it.
        if not _device_proved(request, _AGENT_DOMAIN, raw, desk):
            return JSONResponse(dict(_NOT_PAIRED_DEVICE), status_code=401)
        body = _parse_fields(raw, ("intent_id",))
        if body is None:
            return _bad_request()
        started = handoff.start(body["intent_id"])
        if started.get("error") == "busy":
            return JSONResponse(started, status_code=409)
        if "error" in started:
            return JSONResponse(started, status_code=404)
        return JSONResponse(started, status_code=202)

    async def agent_status(request: Request) -> Response:
        if handoff is None:
            return _model_off()
        return JSONResponse(handoff.status())

    drafting = {"draft": False, "voice": False}

    async def draft_text(request: Request) -> Response:
        if not _same_site(request, "application/json"):
            return _bad_request()
        if intake is None:
            return _model_off()
        with _one_at_a_time(drafting, "draft") as free:
            if not free:
                return _draft_busy()
            raw = await _capped_body(request, _MAX_BODY)
            if raw is None:
                return _bad_request()
            if not _device_proved(request, _DRAFT_DOMAIN, raw, desk):
                return JSONResponse(dict(_NOT_PAIRED_DEVICE), status_code=401)
            body = _parse_fields(raw, ("text",))
            if body is None or not 1 <= len(body["text"]) <= _MAX_TEXT:
                return _bad_request()
            return await _draft(intake.from_text, body["text"])

    async def draft_voice(request: Request) -> Response:
        if not _same_site(request, "audio/wav"):
            return _bad_request()
        if intake is None:
            return _model_off()
        with _one_at_a_time(drafting, "voice") as free:
            if not free:
                return _draft_busy()
            audio = await _capped_body(request, MAX_WAV_BYTES)
            if audio is None:
                return JSONResponse({"error": "audio too large"}, status_code=413)
            if not _device_proved(request, _VOICE_DOMAIN, audio, desk):
                return JSONResponse(dict(_NOT_PAIRED_DEVICE), status_code=401)
            return await _draft(intake.from_voice, audio)

    async def holder(request: Request) -> Response:
        body = await _fields(request, "public_key", "pairing")
        key = _decode(body["public_key"]) if body else None
        # Checked before spending so a malformed key does not burn the token.
        if body is None or key is None or len(key) != _KEY_LEN:
            return _bad_request()
        if not pairing.spend(body["pairing"]):
            return _bad_request()
        return JSONResponse({"registered": desk.register_holder(key)})

    async def keys(request: Request) -> Response:
        """Publish the gate key and the paired holder keys.

        Holder keys are published so a holder can check their own disclosure.
        """
        return JSONResponse(
            {
                "gate_key": _b64(desk.gate_public_key),
                "holder_keys": [_b64(key) for key in desk.holder_keys],
            }
        )

    async def registry(request: Request) -> Response:
        return JSONResponse({"seal": desk.latest_seal()})

    async def receipt(request: Request) -> Response:
        query = dict(request.query_params)
        if query.keys() - {"disclose"} or query.get("disclose", "all") != "all":
            return _bad_request()
        everything = "disclose" in query
        if everything and not _loopback_only(request):
            return JSONResponse({"error": "holder copy is local only"}, status_code=403)
        found = desk.proof_receipt(request.path_params["payment_id"])
        if found is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        # The holder copy stays on this origin; anything shared leaves without
        # the personal fields unless the holder adds them.
        return JSONResponse(found if everything else present(found, frozenset()))

    async def device(request: Request) -> Response:
        keys = desk.holder_keys
        fingerprint = hashlib.sha256(keys[0]).hexdigest()[:16] if keys else None
        return JSONResponse(
            {
                "paired": bool(keys),
                "fingerprint": fingerprint,
                # Read-only, so the holder page offers the microphone only when
                # the desk would answer.
                "voice": voice is not None and voice.available,
            }
        )

    transcribed: dict[str, set[bytes]] = {}
    uploading = False

    async def voice_text(request: Request) -> Response:
        nonlocal uploading
        if not _same_site(request, "audio/wav"):
            return _bad_request()
        if voice is None or not voice.available:
            reason = VOICE_OFF if voice is None else voice.reason
            return JSONResponse(
                {"error": "voice unavailable", "reason": reason}, status_code=503
            )
        quote_id = request.query_params.get("quote")
        shown = next((q for q in desk.pending() if q["quote_id"] == quote_id), None)
        if quote_id is None or shown is None or not desk.holder_keys:
            return _bad_request()
        consent = shown["consent"]
        if desk.expired(consent["expires_at"]):
            return JSONResponse({"error": "quote expired"}, status_code=409)
        signature = _voice_signature(request)
        if signature is None:
            return JSONResponse(dict(_NOT_PAIRED_DEVICE), status_code=401)
        # A signed clip is transcribed once per quote; forget closed quotes.
        open_ids = {q["quote_id"] for q in desk.pending()}
        for closed in transcribed.keys() - open_ids:
            del transcribed[closed]
        if signature in transcribed.get(quote_id, ()):
            return JSONResponse({"error": "clip already transcribed"}, status_code=409)
        # Claimed before the body is read, so parallel fake uploads cannot each
        # buffer a full clip. The loop is single-threaded: no await in between.
        if uploading:
            return JSONResponse({"error": "voice busy"}, status_code=409)
        uploading = True
        try:
            return await _transcribe(request, voice, quote_id, signature, consent)
        finally:
            uploading = False

    async def _transcribe(
        request: Request,
        voice: Transcriber,
        quote_id: str,
        signature: bytes,
        consent: dict[str, Any],
    ) -> Response:
        audio = await _capped_body(request, MAX_WAV_BYTES)
        if audio is None:
            return JSONResponse({"error": "audio too large"}, status_code=413)
        # The digest covers the body actually received, so a signature over
        # other audio or another quote fails here, before any model call.
        if not verify_voice(quote_id, audio, signature, desk.holder_keys):
            return JSONResponse(dict(_NOT_PAIRED_DEVICE), status_code=401)
        transcribed.setdefault(quote_id, set()).add(signature)
        keywords = (consent["recipient"], consent["reference"])
        try:
            heard = await anyio.to_thread.run_sync(voice.transcribe, audio, keywords)
        except ValueError as err:
            return JSONResponse({"error": str(err)}, status_code=400)
        except VoiceBusyError:
            return JSONResponse({"error": "voice busy"}, status_code=409)
        except VoiceAPIError:
            return JSONResponse({"error": "model error"}, status_code=502)
        return JSONResponse({"transcript": heard.text})

    async def page(request: Request) -> Response:
        return FileResponse(_WEBAPP / "index.html", headers=dict(_PAGE_HEADERS))

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

    async def posture(request: Request) -> Response:
        if hub is None:
            return _bad_request()
        return JSONResponse(
            provenance(hub, desk), headers={"cache-control": "no-store"}
        )

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
            ("/api/provenance", posture),
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
        ("/api/device", "GET", device),
        ("/api/keys", "GET", keys),
        ("/api/registry", "GET", registry),
        ("/api/receipt/{payment_id}", "GET", receipt),
        ("/api/voice", "POST", voice_text),
        ("/api/intent", "POST", sign_intent),
        ("/api/intent/draft", "POST", draft_text),
        ("/api/intent/voice", "POST", draft_voice),
        ("/api/agent/start", "POST", agent_start),
        ("/api/agent", "GET", agent_status),
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


def _loopback_only(request: Request) -> bool:
    # Not authentication: anyone who can open a loopback connection to the
    # desk passes. It keeps the holder copy off every remote or proxied path.
    client = request.client.host if request.client else None
    return (
        client in _LOOPBACK_CLIENTS
        and request.url.hostname in _LOCAL_HOSTS
        and not any(name in request.headers for name in _PROXY_HEADERS)
    )


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
    """Console entry point: `mandate-desk [--host H] [--port P] [--voice]`.

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
    parser.add_argument(
        "--voice",
        action="store_true",
        help="let the holder page transcribe spoken confirmations (spends Meta calls)",
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
    voice = transcriber_from_env(os.environ, enabled=args.voice)
    app = build_server(desk, token, allowed, voice=voice).streamable_http_app()
    print(
        f"Pair the holder device: http://{args.host}:{args.port}/app/#pair={token}",
        flush=True,
    )
    uvicorn.run(app, host=args.host, port=args.port)
