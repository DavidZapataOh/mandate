import json
import os
import re

import httpx
import pytest

from bank import increase
from bank.api import PaymentRequest, RailError, ReplayError
from bank.conftest import SENTINEL_KEY, Cassette, named_accounts, recorded
from bank.credentials import BANK_KEY_ENV
from bank.increase import IncreaseRail, ensure_accounts, sandbox_client, setup_cli


def test_client_ignores_a_base_url_from_the_environment(monkeypatch):
    monkeypatch.setenv("INCREASE_BASE_URL", "https://evil.example")
    assert str(sandbox_client(SENTINEL_KEY).base_url).rstrip("/") == (
        "https://sandbox.increase.com"
    )


ACCOUNTS = {"checking-881": "account_payer", "acme-991": "account_payee"}
KEY = "mandate-cert-" + "c1" * 16
REQUEST = PaymentRequest("checking-881", "acme-991", 20000, "USD", "A-991")


def _rail(*answers):
    cassette = Cassette(*answers)
    return IncreaseRail(cassette.client(), ACCOUNTS), cassette


def _body(request):
    return json.loads(request.content)


def test_execute_posts_one_keyed_account_transfer():
    rail, cassette = _rail("account_transfer")
    payment = rail.execute(REQUEST, "h1", KEY)
    [sent] = cassette.requests
    assert (sent.method, str(sent.url)) == (
        "POST",
        "https://sandbox.increase.com/account_transfers",
    )
    assert sent.headers["idempotency-key"] == KEY
    assert sent.headers["authorization"] == f"Bearer {SENTINEL_KEY}"
    assert _body(sent) == {
        "account_id": "account_payer",
        "amount": 20000,
        "description": f"Mandate A-991 {KEY}",
        "destination_account_id": "account_payee",
        "require_approval": False,
    }
    transfer = recorded("account_transfer")["body"]
    assert (payment.payment_id, payment.status) == (transfer["id"], "complete")
    assert (payment.rail, payment.provider, payment.idempotency_key) == (
        "sandbox",
        "increase",
        KEY,
    )
    assert (payment.from_acct, payment.to_acct, payment.action_hash) == (
        "checking-881",
        "acme-991",
        "h1",
    )


@pytest.mark.parametrize(
    "answer", ["account_transfer_replayed", "idempotency_conflict"]
)
def test_a_key_the_bank_already_holds_is_a_replay(answer):
    rail, _ = _rail(answer)
    with pytest.raises(ReplayError):
        rail.execute(REQUEST, "h1", KEY)


def test_refused_overdraft_is_insufficient_funds():
    available = recorded("balance_lookup")["body"]["available_balance"]
    rail, cassette = _rail("insufficient_balance", "balance_lookup")
    big = PaymentRequest("checking-881", "acme-991", available + 1, "USD", "A-991")
    with pytest.raises(ValueError, match="insufficient funds: checking-881"):
        rail.execute(big, "h1", KEY)
    assert str(cassette.requests[1].url) == (
        "https://sandbox.increase.com/accounts/account_payer/balance"
    )


def test_refusal_with_funds_on_hand_is_a_bank_refusal():
    rail, _ = _rail("insufficient_balance", "balance_lookup")
    small = PaymentRequest("checking-881", "acme-991", 1, "USD", "A-991")
    with pytest.raises(RailError, match="^bank: refused$"):
        rail.execute(small, "h1", KEY)


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (httpx.ConnectError("down"), "bank: outcome unknown"),
        (httpx.ReadTimeout("slow"), "bank: outcome unknown"),
        (
            (500, {"type": "internal_server_error", "status": 500}),
            "bank: outcome unknown",
        ),
        ((401, {"type": "invalid_api_key_error", "status": 401}), "bank: unavailable"),
        (
            (403, {"type": "environment_mismatch_error", "status": 403}),
            "bank: unavailable",
        ),
        ((429, {"type": "rate_limited_error", "status": 429}), "bank: unavailable"),
        ((400, {"type": "invalid_parameters_error", "status": 400}), "bank: refused"),
    ],
)
def test_bank_failures_map_to_pinned_reasons(answer, reason):
    rail, _ = _rail(answer)
    with pytest.raises(RailError) as raised:
        rail.execute(REQUEST, "h1", KEY)
    assert str(raised.value) == reason


def test_transfer_left_pending_is_not_a_payment():
    saved = recorded("account_transfer")["body"]
    rail, _ = _rail((200, dict(saved, status="pending_approval")))
    with pytest.raises(RailError, match="^bank: not complete$"):
        rail.execute(REQUEST, "h1", KEY)


def test_unknown_account_or_missing_key_sends_nothing():
    rail, cassette = _rail()
    evil = PaymentRequest("checking-881", "evil-666", 20000, "USD", "A-991")
    with pytest.raises(ValueError, match="unknown account: evil-666"):
        rail.execute(evil, "h1", KEY)
    with pytest.raises(ValueError, match="need an idempotency key"):
        rail.execute(REQUEST, "h1")
    assert cassette.requests == []


def test_balance_is_the_available_balance():
    rail, _ = _rail("balance_lookup")
    available = recorded("balance_lookup")["body"]["available_balance"]
    assert rail.get_balance("checking-881") == available
    with pytest.raises(ValueError, match="unknown account: nope"):
        rail.get_balance("nope")


def test_connect_addresses_open_accounts_by_name():
    cassette = Cassette("accounts_list")
    rail = IncreaseRail.connect(cassette.client())
    listed = recorded("accounts_list")["body"]["data"]
    assert repr(rail) == (
        f"IncreaseRail(sandbox, accounts={sorted(a['name'] for a in listed)})"
    )
    assert SENTINEL_KEY not in repr(rail)


def test_setup_opens_missing_accounts_and_funds_the_payer():
    available = recorded("balance_lookup")["body"]["available_balance"]
    cassette = Cassette(
        "accounts_list",
        "account",
        "account",
        "balance_lookup",
        "account_number",
        "inbound_ach_transfer",
    )
    ensure_accounts(
        cassette.client(),
        ("checking-881", "acme-991"),
        "checking-881",
        available + 5000,
    )
    sent = [(r.method, r.url.path) for r in cassette.requests]
    assert sent == [
        ("GET", "/accounts"),
        ("POST", "/accounts"),
        ("POST", "/accounts"),
        ("GET", f"/accounts/{recorded('account')['body']['id']}/balance"),
        ("POST", "/account_numbers"),
        ("POST", "/simulations/inbound_ach_transfers"),
    ]
    keys = [cassette.requests[i].headers["idempotency-key"] for i in (1, 2, 4)]
    assert keys == [
        "mandate-setup-account-checking-881",
        "mandate-setup-account-acme-991",
        "mandate-setup-number-checking-881",
    ]
    assert _body(cassette.requests[1]) == {"name": "checking-881"}
    assert _body(cassette.requests[5])["amount"] == 5000


def test_setup_cli_needs_the_key(monkeypatch, capsys):
    monkeypatch.delenv(BANK_KEY_ENV, raising=False)
    with pytest.raises(SystemExit) as stopped:
        setup_cli([])
    assert stopped.value.code == 2
    assert capsys.readouterr().err == (
        "bank rail unavailable: set INCREASE_SANDBOX_API_KEY\n"
    )


def test_setup_cli_reports_balances_never_the_key(monkeypatch, capsys):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    available = recorded("balance_lookup")["body"]["available_balance"]
    listed = named_accounts("checking-881", "acme-991")
    cassette = Cassette(listed, "balance_lookup", listed, "balance_lookup")
    monkeypatch.setattr(increase, "sandbox_client", lambda key: cassette.client())
    setup_cli(["--fund-cents", str(available)])
    assert capsys.readouterr().out == (
        "Sandbox accounts ready: checking-881, acme-991\n"
        f"checking-881 available: {available} cents\n"
    )
    assert [r.method for r in cassette.requests] == ["GET", "GET", "GET", "GET"]


SANDBOX_TRANSFER = re.compile(r"(sandbox_)?account_transfer_[A-Za-z0-9]{1,64}")


def _sandbox_account(name, account_id, status="open"):
    return dict(recorded("account")["body"], name=name, id=account_id, status=status)


def test_sandbox_prefixed_ids_are_used_as_the_bank_gives_them():
    payer = recorded("account")["body"]["id"]
    payee = recorded("account_transfer")["body"]["destination_account_id"]
    assert payer.startswith("sandbox_account_")
    listed = {
        "data": [
            _sandbox_account("checking-881", payer),
            _sandbox_account("acme-991", payee),
            _sandbox_account("old-001", "sandbox_account_closed1", "closed"),
        ],
        "next_cursor": None,
    }
    cassette = Cassette((200, listed), "account_transfer")
    rail = IncreaseRail.connect(cassette.client())
    assert repr(rail) == "IncreaseRail(sandbox, accounts=['acme-991', 'checking-881'])"
    assert rail.holds(("checking-881", "acme-991"))
    assert not rail.holds(("checking-881", "old-001"))
    payment = rail.execute(REQUEST, "h1", KEY)
    sent = _body(cassette.requests[1])
    assert (sent["account_id"], sent["destination_account_id"]) == (payer, payee)
    assert payment.payment_id.startswith("sandbox_account_transfer_")
    assert SANDBOX_TRANSFER.fullmatch(payment.payment_id)
    assert SANDBOX_TRANSFER.fullmatch("account_transfer_t1")


def test_setup_keeps_accounts_it_already_holds():
    listed = named_accounts("checking-881", "acme-991")
    cassette = Cassette(listed, "balance_lookup")
    ids = ensure_accounts(
        cassette.client(), ("checking-881", "acme-991"), "acme-991", 1
    )
    assert ids == {
        "checking-881": "account_checking-881",
        "acme-991": "account_acme-991",
    }
    assert [r.method for r in cassette.requests] == ["GET", "GET"]


def test_setup_cli_reports_a_refused_key(monkeypatch, capsys):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    cassette = Cassette((401, {"type": "invalid_api_key_error", "status": 401}))
    monkeypatch.setattr(increase, "sandbox_client", lambda key: cassette.client())
    with pytest.raises(SystemExit) as stopped:
        setup_cli([])
    assert stopped.value.code == 2
    captured = capsys.readouterr()
    assert captured.err == "bank rail unavailable: the sandbox refused the key\n"
    assert SENTINEL_KEY not in captured.out + captured.err


def test_setup_cli_removes_the_key_from_its_environment(monkeypatch):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    listed = named_accounts("checking-881", "acme-991")
    cassette = Cassette(listed, "balance_lookup", listed, "balance_lookup")
    seen = []

    def client(key):
        seen.append((key, BANK_KEY_ENV in os.environ))
        return cassette.client()

    monkeypatch.setattr(increase, "sandbox_client", client)
    setup_cli(["--fund-cents", "1"])
    assert seen == [(SENTINEL_KEY, False)]
