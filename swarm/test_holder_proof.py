import base64
import json

import httpx2
import pytest

from evidence.conftest import ACCT, NONCE, NOTARY, fake_binary
from swarm.holder_proof import cli

KEY = "holder_key_SENTINEL_51c2"
DESK = "http://127.0.0.1:8799"
ZK_REF = "ev:zktls-attestation:c1cda26362828b69266512052b97cb37"
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
PROVEN = {
    "status": "proven",
    "intent_id": "i:000001",
    "evidence_ref": ZK_REF,
    "server": "sandbox.increase.com",
    "session_time": 1800000995,
}
PROVER = (
    "import json, os, sys\n"
    "a = sys.argv[1:]\n"
    "assert a[:-1] == ['prove', '--notary', '127.0.0.1:7047', '--host', "
    f"'sandbox.increase.com', '--path', '/accounts/{ACCT}/balance', "
    f"'--nonce', '{NONCE}', '--reveal', 'account_id,available_balance', "
    "'--auth-env', 'INCREASE_HOLDER_API_KEY', '--out']\n"
    f"assert os.environ['INCREASE_HOLDER_API_KEY'] == '{KEY}'\n"
    "open(a[-1], 'wb').write(b'proof')\n"
    "print(json.dumps({'ok': True, 'status': 200}))"
)


def _desk(proof_answer):
    sent = []
    answers = {
        "/api/intent/funds-challenge": CHALLENGE,
        "/api/intent/funds-proof": proof_answer,
    }

    def handle(request):
        sent.append((request.url.path, json.loads(request.content)))
        return httpx2.Response(200, json=answers[request.url.path])

    return sent, httpx2.Client(transport=httpx2.MockTransport(handle))


def _run(client):
    cli(["--desk", DESK, "--intent", "i:000001"], http_client=client)


def test_holder_cli_proves_and_uploads(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("INCREASE_HOLDER_API_KEY", KEY)
    monkeypatch.setenv("MANDATE_ZKTLS_BIN", fake_binary(tmp_path, PROVER))
    sent, client = _desk(PROVEN)
    _run(client)
    assert capsys.readouterr().out == f"Funds proven for i:000001: {ZK_REF}\n"
    assert sent == [
        ("/api/intent/funds-challenge", {"intent_id": "i:000001"}),
        (
            "/api/intent/funds-proof",
            {
                "intent_id": "i:000001",
                "presentation": base64.b64encode(b"proof").decode(),
            },
        ),
    ]


def test_holder_cli_reports_a_refusal(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("INCREASE_HOLDER_API_KEY", KEY)
    monkeypatch.setenv("MANDATE_ZKTLS_BIN", fake_binary(tmp_path, PROVER))
    denied = {
        "status": "denied",
        "intent_id": "i:000001",
        "reason": "zktls: insufficient funds",
    }
    _, client = _desk(denied)
    with pytest.raises(SystemExit) as stopped:
        _run(client)
    assert stopped.value.code == 1
    out = capsys.readouterr().out
    assert out == "Funds proof refused: zktls: insufficient funds\n"


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({}, "holder proof unavailable: set INCREASE_HOLDER_API_KEY"),
        (
            {"INCREASE_HOLDER_API_KEY": KEY},
            "holder proof unavailable: set MANDATE_ZKTLS_BIN to a built mandate-zktls",
        ),
    ],
)
def test_holder_cli_needs_its_key_and_the_binary(monkeypatch, capsys, env, message):
    monkeypatch.delenv("INCREASE_HOLDER_API_KEY", raising=False)
    monkeypatch.delenv("MANDATE_ZKTLS_BIN", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(SystemExit) as stopped:
        _run(_desk(PROVEN)[1])
    assert (stopped.value.code, capsys.readouterr().err) == (2, message + "\n")


def test_holder_cli_never_prints_the_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("INCREASE_HOLDER_API_KEY", KEY)
    failing = (
        "import json\n"
        "print(json.dumps({'ok': False, 'error': 'tls error: handshake failed'}))\n"
        "raise SystemExit(1)"
    )
    monkeypatch.setenv("MANDATE_ZKTLS_BIN", fake_binary(tmp_path, failing))
    with pytest.raises(SystemExit) as stopped:
        _run(_desk(PROVEN)[1])
    seen = capsys.readouterr()
    assert stopped.value.code == 1
    assert seen.out == "Funds proof refused: tls error: handshake failed\n"
    assert KEY not in seen.out + seen.err


def test_holder_cli_stops_before_proving_a_closed_challenge(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("INCREASE_HOLDER_API_KEY", KEY)
    never = "raise SystemExit('the prover must not run')"
    monkeypatch.setenv("MANDATE_ZKTLS_BIN", fake_binary(tmp_path, never))
    sent = []

    def handle(request):
        sent.append(request.url.path)
        return httpx2.Response(
            200,
            json={
                "status": "unavailable",
                "intent_id": "i:000001",
                "reason": "zktls: not configured",
            },
        )

    with pytest.raises(SystemExit) as stopped:
        _run(httpx2.Client(transport=httpx2.MockTransport(handle)))
    assert stopped.value.code == 1
    assert capsys.readouterr().out == "Funds proof refused: zktls: not configured\n"
    assert sent == ["/api/intent/funds-challenge"]
