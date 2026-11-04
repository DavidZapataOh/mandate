import dataclasses
import hashlib
import json

import pytest

from evidence import zktls
from evidence.conftest import (
    ACCT,
    NONCE,
    NOTARY,
    NOW,
    H,
    fake_binary,
    increase_body,
    increase_disclosed,
    increase_recv,
    verifier_line,
)
from evidence.zktls import (
    BankProofSetup,
    ZktlsError,
    check_balance,
    find_verifier,
    read_output,
    run_verifier,
)

PRESENTATION = b"presentation-bytes"
GOOD = increase_disclosed()
SENT, RECV = GOOD.sent, GOOD.recv


def _check(d=GOOD, account=ACCT, nonce=NONCE, now=NOW):
    return check_balance(
        d, PRESENTATION, notary_key=NOTARY, account_id=account, nonce=nonce, now=now
    )


def test_a_fresh_bound_balance_lookup_is_accepted():
    proof = _check()
    digest = hashlib.sha256(PRESENTATION).hexdigest()
    assert proof == zktls.BalanceProof(
        evidence_ref=f"ev:zktls-attestation:{digest[:32]}",
        presentation_sha256=digest,
        account_id=ACCT,
        available_balance=50000,
        session_time=NOW - 5,
        notary_key=NOTARY,
    )


def _sent(old, new):
    return dataclasses.replace(GOOD, sent=SENT.replace(old, new))


def _recv(old, new):
    return dataclasses.replace(GOOD, recv=RECV.replace(old, new))


def _body(old, new):
    """Edit the body and keep the revealed content-length in step with it."""
    body = increase_body().replace(old, new)
    return dataclasses.replace(GOOD, recv=increase_recv(body))


@pytest.mark.parametrize(
    ("disclosed", "now", "reason"),
    [
        (dataclasses.replace(GOOD, notary_key="03" + "00" * 32), NOW, "wrong notary"),
        (
            dataclasses.replace(GOOD, server_name="api.increase.com"),
            NOW,
            "wrong server",
        ),
        (GOOD, NOW + 296, "stale session"),
        (GOOD, NOW - 36, "session in the future"),
        (_sent("/balance", "/statement"), NOW, "wrong request"),
        (_sent("host: sandbox.increase.com", f"host: {H * 20}"), NOW, "wrong request"),
        (_sent(ACCT, "account_other"), NOW, "different account"),
        (
            _sent(f"mandate-nonce: {NONCE}", f"mandate-nonce: {H * 64}"),
            NOW,
            "not bound to this intent",
        ),
        (_recv("200 OK", "401 Unauthorized"), NOW, "bank did not answer 200"),
        (_recv(f'"{ACCT}"', f'"{H * 28}"'), NOW, "account not disclosed"),
        (
            _body(f'"account_id": "{ACCT}"', '"account_id": "account_other"'),
            NOW,
            "different account",
        ),
        (_recv("50000", f"{H}0000"), NOW, "balance not disclosed"),
        (
            _recv(f"{H * 60}", f',"available_balance": 1{H * 37}'),
            NOW,
            "balance not disclosed",
        ),
    ],
)
def test_each_refusal_names_its_reason(disclosed, now, reason):
    with pytest.raises(ZktlsError, match=f"^zktls: {reason}$"):
        _check(disclosed, now=now)


def _two_responses(first_head_hidden):
    """Two exchanges on one keep-alive session; only the second's balance shows."""
    first_body = H * 120
    if first_head_hidden:
        first = f"HTTP/1.1 200 OK\r\n{H * 90}\r\n{first_body}"
    else:
        first = increase_recv(first_body)
    second = f"{H * 150}\r\n\r\n" + increase_body(99999999)
    return dataclasses.replace(
        GOOD,
        sent=SENT.replace("connection: close\r\n", ""),
        recv=first + second,
    )


@pytest.mark.parametrize("first_head_hidden", [True, False])
def test_a_second_response_on_a_kept_alive_session_is_refused(first_head_hidden):
    smuggled = _two_responses(first_head_hidden)
    with pytest.raises(ZktlsError):
        _check(smuggled)
    # Even with the request asking to close, the response side alone refuses it.
    closed = dataclasses.replace(smuggled, sent=SENT)
    reason = "response head hidden" if first_head_hidden else "not one response"
    with pytest.raises(ZktlsError, match=f"^zktls: {reason}$"):
        _check(closed)


@pytest.mark.parametrize(
    ("disclosed", "reason"),
    [
        (_sent("connection: close\r\n", ""), "request not closed"),
        (_sent("connection: close", "connection: keep-alive"), "request not closed"),
        (
            dataclasses.replace(GOOD, sent=SENT + f"GET /accounts/{ACCT}/balance "),
            "not one request",
        ),
        (
            dataclasses.replace(GOOD, sent=SENT + "GET /x HTTP/1.1\r\nhost: a\r\n\r\n"),
            "not one request",
        ),
        (_sent("accept: application/json", f"accept: {H * 16}"), "not one request"),
        (_sent("authorization: ", f"authorization: {H * 600}"), "not one request"),
        (
            dataclasses.replace(GOOD, sent=SENT.replace("\r\n\r\n", "\r\n")),
            "not one request",
        ),
        (
            _recv("x-request-id: req_5d1e", f"x-request-id: {H * 8}"),
            "response head hidden",
        ),
        (_recv("content-length: ", "x-length: "), "response length not disclosed"),
        (
            dataclasses.replace(
                GOOD,
                recv=increase_recv(increase_body(), "content-length: 147\r\n"),
            ),
            "response length not disclosed",
        ),
        (
            dataclasses.replace(
                GOOD,
                recv=increase_recv(increase_body(), "transfer-encoding: chunked\r\n"),
            ),
            "response length not disclosed",
        ),
        (dataclasses.replace(GOOD, recv=RECV + H), "not one response"),
        (dataclasses.replace(GOOD, recv=RECV[:-1]), "not one response"),
        (dataclasses.replace(GOOD, recv=RECV.split("\r\n\r\n")[0]), "not one response"),
    ],
)
def test_exactly_one_closed_exchange_is_accepted(disclosed, reason):
    with pytest.raises(ZktlsError, match=f"^zktls: {reason}$"):
        _check(disclosed)


def test_header_names_are_matched_without_case():
    upper = _recv("content-length: ", "Content-Length: ")
    assert _check(upper).available_balance == 50000


def test_a_hidden_minus_sign_never_reads_as_a_positive_balance():
    negative = _body('"available_balance": 50000', f'"available_balance": {H}50000')
    with pytest.raises(ZktlsError, match="balance not disclosed"):
        _check(negative)
    assert _check(_body("50000", "-50000")).available_balance == -50000


@pytest.mark.parametrize(
    ("stdout", "reason"),
    [
        ('{"ok":false,"error":"presentation error: merkle"}\n', "presentation invalid"),
        ("not json\n", "verifier output malformed"),
        ("", "verifier output malformed"),
        (
            '{"ok":true,"server_name":"h","time":true,"notary_key":"k","sent":"",'
            '"recv":""}',
            "verifier output malformed",
        ),
    ],
)
def test_verifier_output_refusals(stdout, reason):
    with pytest.raises(ZktlsError, match=f"^zktls: {reason}$"):
        read_output(stdout)


def test_verifier_output_is_read_strictly():
    line = json.dumps(
        {
            "ok": True,
            "server_name": "sandbox.increase.com",
            "time": NOW - 5,
            "notary_key": NOTARY,
            "sent": SENT,
            "recv": RECV,
        }
    )
    assert read_output(f"log line\n{line}\n") == GOOD


def test_run_verifier_passes_the_presentation_file(tmp_path):
    out = {
        "ok": True,
        "server_name": "sandbox.increase.com",
        "time": NOW - 5,
        "notary_key": NOTARY,
        "sent": SENT,
        "recv": RECV,
    }
    body = (
        "import json, sys\n"
        "assert sys.argv[1:3] == ['verify', '--presentation']\n"
        f"assert open(sys.argv[3], 'rb').read() == {PRESENTATION!r}\n"
        f"print(json.dumps({out!r}))"
    )
    assert run_verifier(fake_binary(tmp_path, body), PRESENTATION) == GOOD


def test_run_verifier_refusals(tmp_path, monkeypatch):
    binary = fake_binary(tmp_path, "import time\ntime.sleep(5)")
    with pytest.raises(ZktlsError, match="^zktls: presentation size refused$"):
        run_verifier(binary, b"")
    with pytest.raises(ZktlsError, match="^zktls: presentation size refused$"):
        run_verifier(binary, b"x" * 65_537)
    monkeypatch.setattr(zktls, "VERIFY_TIMEOUT_S", 0.2)
    with pytest.raises(ZktlsError, match="^zktls: verifier timed out$"):
        run_verifier(binary, PRESENTATION)
    with pytest.raises(ZktlsError, match="^zktls: verifier unavailable$"):
        run_verifier(str(tmp_path / "missing"), PRESENTATION)


def test_run_verifier_refuses_a_failing_exit_even_with_good_output(tmp_path):
    body = f"print({verifier_line(GOOD)!r})\nraise SystemExit(3)"
    with pytest.raises(ZktlsError, match="^zktls: presentation invalid$"):
        run_verifier(fake_binary(tmp_path, body), PRESENTATION)


def test_find_verifier_needs_an_executable(tmp_path):
    binary = fake_binary(tmp_path, "")
    assert find_verifier({"MANDATE_ZKTLS_BIN": binary}) == binary
    assert find_verifier({}) is None
    plain = tmp_path / "plain"
    plain.write_text("")
    assert find_verifier({"MANDATE_ZKTLS_BIN": str(plain)}) is None


def test_setup_issues_the_challenge_and_checks_the_account():
    setup = BankProofSetup("unused", "127.0.0.1:7047", NOTARY, {"checking-881": ACCT})
    assert setup.challenge("checking-881", NONCE) == {
        "host": "sandbox.increase.com",
        "path": f"/accounts/{ACCT}/balance",
        "nonce": NONCE,
        "notary": "127.0.0.1:7047",
        "notary_key": NOTARY,
        "reveal": ["account_id", "available_balance"],
    }
    with pytest.raises(ZktlsError, match="^zktls: unknown account$"):
        setup.challenge("acme-991", NONCE)
    with pytest.raises(ZktlsError, match="^zktls: unknown account$"):
        setup.verify(PRESENTATION, "acme-991", NONCE, NOW)
