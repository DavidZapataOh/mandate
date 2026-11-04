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


NEVER = "raise SystemExit('the prover must not run')"


def _answering(challenge):
    sent = []

    def handle(request):
        sent.append(request.url.path)
        return httpx2.Response(200, json=challenge)

    return sent, httpx2.Client(transport=httpx2.MockTransport(handle))


@pytest.mark.parametrize(
    "change",
    [
        {"host": "evil.example.com"},
        {"host": "sandbox.increase.com.evil.example"},
        {"host": "api.increase.com"},
        {"path": "/accounts/account_abc/transactions"},
        {"path": "/accounts/account_abc/balance?at_time=2020-01-01"},
        {"path": "/accounts/../balance"},
        {"path": "/accounts/user_abc/balance"},
        {"path": f"/accounts/account_{'a' * 65}/balance"},
        {"path": "/accounts/account_abc/balance\r\nx: y"},
        {"reveal": ["account_id", "available_balance", "current_balance"]},
        {"reveal": ["available_balance"]},
        {"reveal": "account_id,available_balance"},
        {"nonce": NONCE.upper()},
        {"nonce": NONCE[:-1]},
        {"nonce": "--out=/tmp/x" + NONCE[12:]},
        {"notary": "evil.example.com:7047"},
        {"notary": "10.0.0.5:7047"},
        {"notary": "127.0.0.1"},
        {"notary": "127.0.0.1:0"},
        {"notary": "127.0.0.1:70470"},
        {"notary": 7047},
        {"host": None},
    ],
)
def test_holder_cli_refuses_a_challenge_that_is_not_pinned(
    tmp_path, monkeypatch, capsys, change
):
    monkeypatch.setenv("INCREASE_HOLDER_API_KEY", KEY)
    monkeypatch.setenv("MANDATE_ZKTLS_BIN", fake_binary(tmp_path, NEVER))
    sent, client = _answering({**CHALLENGE, **change})
    with pytest.raises(SystemExit) as stopped:
        _run(client)
    assert stopped.value.code == 1
    seen = capsys.readouterr()
    assert seen.out == "Funds proof refused: desk challenge not pinned\n"
    assert sent == ["/api/intent/funds-challenge"]


@pytest.mark.parametrize(
    "path",
    [
        "/accounts/account_in71c4amph0vgo2qllky/balance",
        "/accounts/sandbox_account_in71c4amph0vgo2qllky/balance",
    ],
)
def test_holder_cli_accepts_both_increase_account_id_forms(
    tmp_path, monkeypatch, capsys, path
):
    monkeypatch.setenv("INCREASE_HOLDER_API_KEY", KEY)
    prover = (
        "import json, sys\n"
        "open(sys.argv[-1], 'wb').write(b'proof')\n"
        "print(json.dumps({'ok': True, 'status': 200}))"
    )
    monkeypatch.setenv("MANDATE_ZKTLS_BIN", fake_binary(tmp_path, prover))
    answers = {
        "/api/intent/funds-challenge": {**CHALLENGE, "path": path},
        "/api/intent/funds-proof": PROVEN,
    }
    client = httpx2.Client(
        transport=httpx2.MockTransport(
            lambda request: httpx2.Response(200, json=answers[request.url.path])
        )
    )
    _run(client)
    assert capsys.readouterr().out == f"Funds proven for i:000001: {ZK_REF}\n"


@pytest.mark.parametrize(
    "desk",
    [
        "http://desk.example.com:8766",
        "http://10.0.0.5:8766",
        "ftp://127.0.0.1:8766",
        "127.0.0.1:8766",
        "http://127.0.0.1.evil.example:8766",
    ],
)
def test_holder_cli_refuses_plain_http_to_a_remote_desk(
    tmp_path, monkeypatch, capsys, desk
):
    monkeypatch.setenv("INCREASE_HOLDER_API_KEY", KEY)
    monkeypatch.setenv("MANDATE_ZKTLS_BIN", fake_binary(tmp_path, NEVER))
    sent, client = _answering(CHALLENGE)
    with pytest.raises(SystemExit) as stopped:
        cli(["--desk", desk, "--intent", "i:000001"], http_client=client)
    assert stopped.value.code == 1
    seen = capsys.readouterr()
    assert seen.out == "Funds proof refused: desk URL must be https or loopback\n"
    assert sent == []


@pytest.mark.parametrize(
    "desk",
    [
        "http://127.0.0.1:8766",
        "http://localhost:8766",
        "http://[::1]:8766",
        "https://desk.example.com",
    ],
)
def test_holder_cli_allows_a_loopback_or_https_desk(tmp_path, monkeypatch, desk):
    monkeypatch.setenv("INCREASE_HOLDER_API_KEY", KEY)
    monkeypatch.setenv("MANDATE_ZKTLS_BIN", fake_binary(tmp_path, PROVER))
    sent, client = _desk(PROVEN)
    cli(["--desk", desk, "--intent", "i:000001"], http_client=client)
    assert [path for path, _ in sent][0] == "/api/intent/funds-challenge"
