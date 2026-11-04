import base64

import anyio
import pytest

from bank.conftest import RecordingRail
from evidence.conftest import (
    ACCT,
    NOTARY,
    NOW,
    fake_binary,
    fake_verifier,
    increase_disclosed,
    verifier_line,
)
from evidence.zktls import BankProofSetup
from swarm.conftest import DEMO_INTENT
from swarm.server import build_server
from swarm.test_server import PAIR, _asgi

ZK_REF = "ev:zktls-attestation:c1cda26362828b69266512052b97cb37"
PROOF_B64 = base64.b64encode(b"proof").decode()


@pytest.fixture
def app(make_desk, tmp_path):
    return _app(make_desk, fake_verifier(tmp_path, increase_disclosed()))


def _app(make_desk, verifier):
    setup = BankProofSetup(
        verifier,
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
    return build_server(desk, PAIR).streamable_http_app()


@pytest.mark.anyio
async def test_challenge_and_proof_routes_round_trip(app):
    async with _asgi(app) as http:
        challenge = await http.post(
            "/api/intent/funds-challenge", json={"intent_id": "i:000001"}
        )
        proof = await http.post(
            "/api/intent/funds-proof",
            json={"intent_id": "i:000001", "presentation": PROOF_B64},
        )
    assert (challenge.status_code, challenge.json()["status"]) == (200, "open")
    assert proof.json() == {
        "status": "proven",
        "intent_id": "i:000001",
        "evidence_ref": ZK_REF,
        "server": "sandbox.increase.com",
        "session_time": NOW - 5,
    }


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("body", "headers"),
    [
        (b'{"intent_id":"i:000001","presentation":"%%%"}', {}),
        (b'{"intent_id":"i:000001"}', {}),
        (b"[]", {}),
        (b'{"intent_id":"i:000001","presentation":"' + b"A" * 98_304 + b'"}', {}),
        (
            b'{"intent_id":"i:000001","presentation":"cHJvb2Y="}',
            {"origin": "http://evil.example"},
        ),
    ],
)
async def test_proof_route_refuses_bad_bodies(app, body, headers):
    async with _asgi(app) as http:
        answer = await http.post(
            "/api/intent/funds-proof",
            content=body,
            headers={"content-type": "application/json", **headers},
        )
    assert (answer.status_code, answer.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
async def test_proof_routes_keep_the_host_allowlist(app):
    async with _asgi(app) as http:
        for path, body in (
            ("/api/intent/funds-challenge", {"intent_id": "i:000001"}),
            (
                "/api/intent/funds-proof",
                {"intent_id": "i:000001", "presentation": PROOF_B64},
            ),
        ):
            answer = await http.post(path, json=body, headers={"host": "evil.example"})
            assert answer.status_code == 400


@pytest.mark.anyio
async def test_proof_route_runs_one_verifier_at_a_time(make_desk, tmp_path):
    slow = fake_binary(
        tmp_path,
        f"import time\ntime.sleep(1)\nprint({verifier_line(increase_disclosed())!r})",
    )
    body = {"intent_id": "i:000001", "presentation": PROOF_B64}
    answers = []
    async with _asgi(_app(make_desk, slow)) as http:

        async def post():
            answers.append(await http.post("/api/intent/funds-proof", json=body))

        async with anyio.create_task_group() as group:
            group.start_soon(post)
            await anyio.sleep(0.3)
            group.start_soon(post)
    assert sorted(a.status_code for a in answers) == [200, 409]
    busy = next(a for a in answers if a.status_code == 409)
    assert busy.json() == {"error": "proof busy"}
