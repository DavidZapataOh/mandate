import base64
import hashlib
import io
import json
import threading
import wave

import anyio
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import Client

from swarm.conftest import DEMO_INTENT, TRACE, message
from swarm.intake import IntentIntake
from swarm.intent import PayeeBook, sign_intent
from swarm.meta_client import MetaAPIError, MetaResponse
from swarm.server import build_server
from swarm.test_server import FOREIGN, PAIR, _asgi
from swarm.voice import Transcript

BOOK = PayeeBook.from_json(
    {"acme corp": {"account": "acme-991", "open_invoices": ["A-991"]}}
)
FIELDS = {
    "amount_cents": 20000,
    "currency": "USD",
    "recipient": "acme-991",
    "reference": "A-991",
}
DRAFT = {
    "payee_name": "Acme Corp",
    "amount_cents": 20000,
    "currency": "USD",
    "reference": "A991",
}
SAID = "Pay my Acme Corp bill A-991, 200 dollars."
INTENT_HASH = "a7a12d73de0370d60b0ea24041a748ee6fc4db6974cf47b3b502f2c7d52b3ed8"
COOP_REF = "ev:cooperative-signed:c97da00074742018dff37a1130a145f3"
BANK = bytes([7]) * 32
WAV_HEADERS = {"content-type": "audio/wav"}
JSON_HEADERS = {"content-type": "application/json"}
SIG = "x-mandate-device-sig"
NOT_PAIRED = {"error": "not the paired device"}


def _sig(key, domain, body):
    digest = hashlib.sha256(body).hexdigest()
    message = f"mandate/intent-{domain}/v1\n{digest}".encode()
    signature = Ed25519PrivateKey.from_private_bytes(key).sign(message)
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


def _text(text, key=None, domain="draft"):
    body = json.dumps({"text": text}).encode()
    headers = dict(JSON_HEADERS)
    if key is not None:
        headers[SIG] = _sig(key, domain, body)
    return {"content": body, "headers": headers}


def _clip(clip, key=None, domain="voice", **extra):
    headers = {**WAV_HEADERS, **extra}
    if key is not None:
        headers[SIG] = _sig(key, domain, clip)
    return {"content": clip, "headers": headers}


class SlowMeta:
    """Test fake model that holds its first call until released."""

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def respond(self, model, input, **kwargs):  # noqa: A002
        self.calls += 1
        self.entered.set()
        self.release.wait(5)
        return MetaResponse(trace=TRACE, output=(message(json.dumps(DRAFT)),))


def _wav(seconds=1, rate=16000):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(2 * rate * seconds))
    return buf.getvalue()


class Ears:
    """Test fake transcriber: records each clip and answers one sentence."""

    def __init__(self):
        self.heard = []

    def __call__(self, audio, keywords):
        self.heard.append((len(audio), keywords))
        return Transcript(SAID, "sess-1", 1000, 5.0)


def _app(desk, intake=None):
    return build_server(desk, PAIR, intake=intake).streamable_http_app()


def _intake(fake_meta, *outputs, ears=None):
    meta = fake_meta(*outputs)
    return IntentIntake(meta, BOOK, ears or Ears()), meta


def _b64(raw):
    return base64.b64encode(raw).decode()


@pytest.mark.anyio
async def test_agent_reads_the_intent_through_its_tool(make_desk):
    desk, _ = make_desk(intents=(DEMO_INTENT,), bank_key=BANK)
    async with Client(build_server(desk, PAIR)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        result = await client.call_tool("get_intent", {"intent_id": "i:000001"})
    schema = tools["quote_payment"].input_schema
    assert "intent_id" in schema["properties"]
    assert "intent_id" not in schema["required"]
    assert json.loads(result.content[0].text) == {
        "status": "signed",
        "intent_id": "i:000001",
        "intent_hash": INTENT_HASH,
        "summary": "Pay 200.00 USD to acme-991 (ref A-991) from checking-881",
        **FIELDS,
        "evidence_ref": COOP_REF,
        "payment_id": None,
    }


@pytest.mark.anyio
async def test_holder_signs_an_intent_over_http(make_desk):
    desk, holder = make_desk(bank_key=BANK)
    body = {"intent": FIELDS, "signature": _b64(sign_intent(holder, DEMO_INTENT))}
    async with _asgi(_app(desk)) as http:
        resp = await http.post("/api/intent", json=body)
    assert resp.status_code == 200
    view = resp.json()
    assert (view["status"], view["intent_id"], view["evidence_ref"]) == (
        "signed",
        "i:000001",
        COOP_REF,
    )
    assert desk.intent_receipt("i:000001")["status"] == "signed"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("body", "headers"),
    [
        ({"signature": "AA=="}, {}),
        ({"intent": {**FIELDS, "extra": 1}, "signature": "AA=="}, {}),
        ({"intent": {**FIELDS, "amount_cents": "20000"}, "signature": "AA=="}, {}),
        ({"intent": {**FIELDS, "amount_cents": True}, "signature": "AA=="}, {}),
        ({"intent": {**FIELDS, "currency": 5}, "signature": "AA=="}, {}),
        ({"intent": FIELDS, "signature": "not base64!"}, {}),
        ({"intent": FIELDS, "signature": "AA=="}, {"origin": "http://evil.example"}),
        ({"intent": FIELDS, "signature": "AA=="}, FOREIGN),
    ],
)
async def test_sign_route_rejects_bad_requests(make_desk, body, headers):
    desk, _ = make_desk()
    async with _asgi(_app(desk)) as http:
        resp = await http.post("/api/intent", json=body, headers=headers)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})
    assert desk.intent_receipt("i:000001")["status"] == "unknown"


@pytest.mark.anyio
async def test_typed_request_becomes_a_draft(make_desk, fake_meta):
    desk, holder = make_desk()
    intake, meta = _intake(fake_meta, [message(json.dumps(DRAFT))])
    async with _asgi(_app(desk, intake)) as http:
        resp = await http.post("/api/intent/draft", **_text(SAID, holder))
    assert (resp.status_code, resp.json()) == (
        200,
        {"status": "drafted", "transcript": SAID, "intent": FIELDS},
    )
    assert meta.requests[0]["input"] == SAID


@pytest.mark.anyio
async def test_draft_that_misses_the_book_is_denied(make_desk, fake_meta):
    desk, holder = make_desk()
    draft = {**DRAFT, "payee_name": "Evil Corp"}
    intake, _ = _intake(fake_meta, [message(json.dumps(draft))])
    async with _asgi(_app(desk, intake)) as http:
        resp = await http.post("/api/intent/draft", **_text(SAID, holder))
    assert resp.json() == {
        "status": "denied",
        "transcript": SAID,
        "reason": "payee not in book: evil corp",
    }


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("text", "code", "error"),
    [
        ("", 400, "bad request"),
        ("x" * 501, 400, "bad request"),
        ("boom", 502, "model error"),
    ],
)
async def test_draft_route_errors(make_desk, fake_meta, text, code, error):
    desk, holder = make_desk()
    intake, _ = _intake(fake_meta, MetaAPIError("HTTP 500: down"))
    async with _asgi(_app(desk, intake)) as http:
        resp = await http.post("/api/intent/draft", **_text(text, holder))
    assert (resp.status_code, resp.json()) == (code, {"error": error})


@pytest.mark.anyio
async def test_spoken_request_becomes_a_draft(make_desk, fake_meta):
    desk, holder = make_desk()
    ears = Ears()
    intake, _ = _intake(fake_meta, [message(json.dumps(DRAFT))], ears=ears)
    clip = _wav()
    async with _asgi(_app(desk, intake)) as http:
        resp = await http.post("/api/intent/voice", **_clip(clip, holder))
    assert resp.json() == {"status": "drafted", "transcript": SAID, "intent": FIELDS}
    assert ears.heard == [(len(clip), ("acme corp", "A-991"))]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("clip", "headers", "code", "error"),
    [
        (_wav(), {"content-type": "text/plain"}, 400, "bad request"),
        (_wav(), {**WAV_HEADERS, "origin": "http://evil.example"}, 400, "bad request"),
        (b"RIFFnope", WAV_HEADERS, 400, "unsupported wav: not a wav file"),
        (_wav(rate=44100), WAV_HEADERS, 400, "unsupported wav: rate=44100"),
        (_wav(seconds=601), WAV_HEADERS, 400, "unsupported wav: longer than 600 s"),
        (bytes(31_000_001), WAV_HEADERS, 413, "audio too large"),
    ],
)
async def test_voice_route_refuses_before_transcribing(
    make_desk, fake_meta, clip, headers, code, error
):
    desk, holder = make_desk()
    ears = Ears()
    intake, meta = _intake(fake_meta, ears=ears)
    headers = {**headers, SIG: _sig(holder, "voice", clip)}
    async with _asgi(_app(desk, intake)) as http:
        resp = await http.post("/api/intent/voice", content=clip, headers=headers)
    assert (resp.status_code, resp.json()) == (code, {"error": error})
    assert (ears.heard, meta.requests) == ([], [])


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("path", "kwargs"),
    [
        ("/api/intent/draft", _text(SAID)),
        ("/api/intent/voice", _clip(_wav())),
    ],
)
async def test_drafting_needs_a_model(make_desk, path, kwargs):
    desk, _ = make_desk()
    async with _asgi(_app(desk)) as http:
        resp = await http.post(path, **kwargs)
    assert (resp.status_code, resp.json()) == (503, {"error": "model unavailable"})


def _forged(path, other):
    holder = bytes([9]) * 32
    if path.endswith("draft"):
        return [
            _text(SAID),
            _text(SAID, holder),
            {
                **_text(SAID),
                "headers": {**JSON_HEADERS, SIG: _sig(other, "draft", b"x")},
            },
            {
                **_text(SAID),
                "headers": {**JSON_HEADERS, SIG: _sig(other, "voice", b"x")},
            },
        ]
    clip = _wav()
    return [
        _clip(clip),
        _clip(clip, holder),
        _clip(clip, **{SIG: _sig(other, "voice", b"other body")}),
        _clip(clip, other, domain="draft"),
    ]


@pytest.mark.anyio
@pytest.mark.parametrize("path", ["/api/intent/draft", "/api/intent/voice"])
@pytest.mark.parametrize("which", range(4))
async def test_drafting_needs_the_paired_device(make_desk, fake_meta, path, which):
    desk, holder = make_desk()
    ears = Ears()
    intake, meta = _intake(fake_meta, [message(json.dumps(DRAFT))], ears=ears)
    kwargs = _forged(path, holder)[which]
    async with _asgi(_app(desk, intake)) as http:
        resp = await http.post(path, **kwargs)
    assert (resp.status_code, resp.json()) == (401, NOT_PAIRED)
    assert (ears.heard, meta.requests) == ([], [])


@pytest.mark.anyio
@pytest.mark.parametrize("path", ["/api/intent/draft", "/api/intent/voice"])
async def test_one_draft_at_a_time(make_desk, path):
    desk, holder = make_desk()
    slow = SlowMeta()
    intake = IntentIntake(slow, BOOK, Ears())
    kwargs = _text(SAID, holder) if path.endswith("draft") else _clip(_wav(), holder)
    results = []

    async def first(http):
        results.append(await http.post(path, **kwargs))

    async with _asgi(_app(desk, intake)) as http, anyio.create_task_group() as tg:
        tg.start_soon(first, http)
        with anyio.fail_after(5):
            while not slow.entered.is_set():
                await anyio.sleep(0.01)
        busy = await http.post(path, **kwargs)
        slow.release.set()
    assert (busy.status_code, busy.json()) == (409, {"error": "draft busy"})
    assert results[0].status_code == 200
    assert slow.calls == 1
