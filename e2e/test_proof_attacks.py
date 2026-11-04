import base64
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import time

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from bank.conftest import RecordingRail
from bank.credentials import HOLDER_KEY_ENV, WEBHOOK_SECRET_ENV
from e2e.attack_world import ROOT
from evidence.conftest import (
    ACCT,
    NONCE,
    NOTARY,
    NOW,
    H,
    fake_binary,
    fake_verifier,
    increase_body,
    increase_disclosed,
    increase_recv,
)
from evidence.zktls import BankProofSetup
from gate.consent import Consent, consent_bytes
from swarm.conftest import DEMO_INTENT, FakeMeta, message
from swarm.intake import IntentIntake
from swarm.intent import PayeeBook
from swarm.server import build_server
from swarm.voice import voice_bytes

JSON = {"content-type": "application/json"}
SIG = "x-mandate-device-sig"
NOT_PAIRED = (401, {"error": "not the paired device"})
START = b'{"intent_id": "i:000001"}'
TEXT = b'{"text": "Pay my Acme Corp bill A-991, 200 dollars."}'
BOOK = PayeeBook.from_json(
    {"acme corp": {"account": "acme-991", "open_invoices": ["A-991"]}}
)
DRAFT = {
    "payee_name": "Acme Corp",
    "amount_cents": 20000,
    "currency": "USD",
    "reference": "A991",
}
HOLDER_PROOF = (sys.executable, "-c", "from swarm.holder_proof import cli; cli()")
HOLDER_KEY = "holder_key_SENTINEL_51c2"
WEBHOOK_SECRET = "webhook_secret_SENTINEL_7d40"  # noqa: S105
CHALLENGE = {
    "status": "open",
    "intent_id": "i:000001",
    "host": "sandbox.increase.com",
    "path": f"/accounts/{ACCT}/balance",
    "nonce": NONCE,
    "notary": "127.0.0.1:7047",
    "notary_key": NOTARY,
    "reveal": ["account_id", "available_balance"],
}
PROOF = {"intent_id": "i:000001", "presentation": base64.b64encode(b"proof").decode()}


def _signed(key: bytes, message: bytes) -> str:
    raw = Ed25519PrivateKey.from_private_bytes(key).sign(message)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _domain(domain: str, body: bytes) -> bytes:
    return f"{domain}\n{hashlib.sha256(body).hexdigest()}".encode()


@pytest.fixture
def device_desk(make_desk, serve):
    desk, holder = make_desk(intents=(DEMO_INTENT,))
    agent = FakeMeta([message("I will not pay.")], [message("I will not pay.")])
    drafter = FakeMeta([message(json.dumps(DRAFT))])
    intake = IntentIntake(drafter, BOOK, lambda audio, words: None)
    app = build_server(desk, "pair-x", intake=intake, agent=agent)
    return serve(app.streamable_http_app()), holder, agent, drafter


def _consent_signature(holder: bytes) -> str:
    consent = Consent(20000, "USD", "acme-991", "A-991", "checking-881", "n1", 9, b"")
    return _signed(holder, consent_bytes(consent))


FORGED_STARTS = [
    ("no signature", lambda holder: None),
    (
        "signed for drafting",
        lambda holder: _signed(holder, _domain("mandate/intent-draft/v1", START)),
    ),
    (
        "signed for a spoken draft",
        lambda holder: _signed(holder, _domain("mandate/intent-voice/v1", START)),
    ),
    (
        "a voice clip signature",
        lambda holder: _signed(holder, voice_bytes("q:000001", START)),
    ),
    ("a consent signature", _consent_signature),
    (
        "signed over another body",
        lambda holder: _signed(
            holder, _domain("mandate/agent-start/v1", b'{"intent_id": "i:000002"}')
        ),
    ),
    (
        "signed by a key that never paired",
        lambda holder: _signed(b"\x09" * 32, _domain("mandate/agent-start/v1", START)),
    ),
]


@pytest.mark.parametrize(
    "forge", [f for _, f in FORGED_STARTS], ids=[n for n, _ in FORGED_STARTS]
)
def test_a_forged_device_proof_spends_no_model_call(device_desk, forge):
    url, holder, agent, _ = device_desk
    signature = forge(holder)
    headers = JSON if signature is None else {**JSON, SIG: signature}
    answer = httpx2.post(f"{url}/api/agent/start", content=START, headers=headers)
    assert (answer.status_code, answer.json()) == NOT_PAIRED
    assert agent.requests == []


def test_a_draft_signature_is_refused_on_the_agent_and_the_reverse(device_desk):
    url, holder, agent, drafter = device_desk
    as_agent = _signed(holder, _domain("mandate/agent-start/v1", TEXT))
    answer = httpx2.post(
        f"{url}/api/intent/draft", content=TEXT, headers={**JSON, SIG: as_agent}
    )
    assert (answer.status_code, answer.json()) == NOT_PAIRED
    own = _signed(holder, _domain("mandate/intent-draft/v1", TEXT))
    drafted = httpx2.post(
        f"{url}/api/intent/draft", content=TEXT, headers={**JSON, SIG: own}
    )
    assert (drafted.status_code, drafted.json()["status"]) == (200, "drafted")
    assert (len(drafter.requests), agent.requests) == (1, [])


@pytest.mark.xfail(
    strict=True,
    reason="device proofs carry no nonce or time: a captured request replays",
)
def test_a_captured_device_request_cannot_be_replayed(device_desk):
    url, holder, agent, _ = device_desk
    headers = {**JSON, SIG: _signed(holder, _domain("mandate/agent-start/v1", START))}
    first = httpx2.post(f"{url}/api/agent/start", content=START, headers=headers)
    assert first.status_code == 202
    deadline = time.monotonic() + 5
    while httpx2.get(f"{url}/api/agent").json()["state"] != "failed":
        if time.monotonic() > deadline:
            pytest.skip("the first run did not end")
        time.sleep(0.02)
    replayed = httpx2.post(f"{url}/api/agent/start", content=START, headers=headers)
    assert replayed.status_code == 401


def _smuggled(head_hidden: bool):
    """Two responses on one kept-alive session; the second shows a balance."""
    first_body = H * 120
    first = (
        f"HTTP/1.1 200 OK\r\n{H * 90}\r\n{first_body}"
        if head_hidden
        else increase_recv(first_body)
    )
    second = f"{H * 150}\r\n\r\n" + increase_body(99999999)
    return dataclasses.replace(increase_disclosed(), recv=first + second)


@pytest.mark.parametrize(
    ("head_hidden", "reason"),
    [(True, "zktls: response head hidden"), (False, "zktls: not one response")],
)
def test_a_balance_smuggled_on_a_kept_alive_session_is_refused(
    make_desk, serve, tmp_path, head_hidden, reason
):
    setup = BankProofSetup(
        fake_verifier(tmp_path, _smuggled(head_hidden)),
        "127.0.0.1:7047",
        NOTARY,
        {"checking-881": ACCT},
    )
    desk, _ = make_desk(
        clock=lambda: NOW,
        bank=RecordingRail(balance=50000),
        intents=(DEMO_INTENT,),
        zktls=setup,
    )
    url = serve(build_server(desk, "pair-x").streamable_http_app())
    opened = httpx2.post(
        f"{url}/api/intent/funds-challenge", json={"intent_id": "i:000001"}
    )
    assert opened.json()["status"] == "open"
    answer = httpx2.post(f"{url}/api/intent/funds-proof", json=PROOF)
    assert answer.json() == {
        "status": "denied",
        "intent_id": "i:000001",
        "reason": reason,
    }
    assert "funds" not in desk.intent_receipt("i:000001")


def _hostile_desk(serve, change: dict[str, object]) -> tuple[str, list[str], list[str]]:
    """A desk that answers the challenge with `change`; every request it saw."""
    asked: list[str] = []
    seen: list[str] = []

    async def record(request: Request) -> None:
        asked.append(request.url.path)
        body = (await request.body()).decode(errors="replace")
        seen.append(f"{request.url}\n{dict(request.headers)}\n{body}")

    async def challenge(request: Request) -> JSONResponse:
        await record(request)
        return JSONResponse({**CHALLENGE, **change})

    async def proof(request: Request) -> JSONResponse:
        await record(request)
        return JSONResponse({"status": "denied", "reason": "zktls: proof refused"})

    app = Starlette(
        routes=[
            Route("/api/intent/funds-challenge", challenge, methods=["POST"]),
            Route("/api/intent/funds-proof", proof, methods=["POST"]),
        ]
    )
    return serve(app), asked, seen


def _holder_proof(desk: str, prover: str) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        HOLDER_KEY_ENV: HOLDER_KEY,
        WEBHOOK_SECRET_ENV: WEBHOOK_SECRET,
        "MANDATE_ZKTLS_BIN": prover,
    }
    return subprocess.run(  # noqa: S603
        [*HOLDER_PROOF, "--desk", desk, "--intent", "i:000001"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _leaked(done: subprocess.CompletedProcess[str], seen: list[str]) -> list[str]:
    said = "".join([done.stdout, done.stderr, *seen])
    return [secret for secret in (HOLDER_KEY, WEBHOOK_SECRET) if secret in said]


@pytest.mark.parametrize(
    "change",
    [
        {"host": "evil.example.com"},
        {"host": "sandbox.increase.com.evil.example"},
        {"notary": "203.0.113.9:7047"},
        {"path": "/accounts/account_abc/transactions"},
    ],
)
def test_a_desk_that_names_its_own_host_never_gets_the_holder_key(
    serve, tmp_path, change
):
    url, asked, seen = _hostile_desk(serve, change)
    ran = tmp_path / "prover-ran"
    done = _holder_proof(
        url, fake_binary(tmp_path, f"open({str(ran)!r}, 'w').write('ran')")
    )
    assert (done.returncode, done.stdout) == (
        1,
        "Funds proof refused: desk challenge not pinned\n",
    )
    assert _leaked(done, seen) == []
    assert (ran.exists(), asked) == (False, ["/api/intent/funds-challenge"])


def test_a_desk_that_asks_honestly_still_sees_no_bank_credential(serve, tmp_path):
    url, asked, seen = _hostile_desk(serve, {})
    ran = tmp_path / "prover-ran"
    prover = fake_binary(
        tmp_path,
        "import sys\n"
        f"open({str(ran)!r}, 'w').write('ran')\n"
        "open(sys.argv[sys.argv.index('--out') + 1], 'wb').write(b'proof')",
    )
    done = _holder_proof(url, prover)
    assert (done.returncode, done.stdout) == (
        1,
        "Funds proof refused: zktls: proof refused\n",
    )
    assert (ran.exists(), asked) == (
        True,
        ["/api/intent/funds-challenge", "/api/intent/funds-proof"],
    )
    assert json.loads(seen[1].rsplit("\n", 1)[1]) == PROOF
    assert _leaked(done, seen) == []


def test_the_holder_key_is_never_sent_to_a_remote_desk_in_clear(tmp_path):
    done = _holder_proof(
        "http://203.0.113.9:8766", fake_binary(tmp_path, "raise SystemExit(3)")
    )
    assert (done.returncode, done.stdout) == (
        1,
        "Funds proof refused: desk URL must be https or loopback\n",
    )
    assert _leaked(done, []) == []
