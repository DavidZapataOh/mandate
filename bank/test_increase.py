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


def _rail(*answers, max_retries=0):
    cassette = Cassette(*answers)
    return IncreaseRail(cassette.client(max_retries), ACCOUNTS), cassette


def _transfer(**change):
    """The recorded transfer, as the bank holds it for REQUEST under KEY."""
    held = {
        "account_id": "account_payer",
        "destination_account_id": "account_payee",
        "amount": 20000,
        "idempotency_key": KEY,
    }
    return {**recorded("account_transfer")["body"], **held, **change}


def _replayed(body):
    return httpx.Response(200, json=body, headers={"idempotent-replayed": "true"})


def _listed(*transfers):
    return 200, {"data": list(transfers), "next_cursor": None}


LOST = httpx.ReadTimeout("response lost after the bank committed")


def _body(request):
    return json.loads(request.content)


def test_execute_posts_one_keyed_account_transfer():
    rail, cassette = _rail((200, _transfer()))
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


def test_a_key_reused_with_other_parameters_is_a_replay():
    rail, _ = _rail("idempotency_conflict")
    with pytest.raises(ReplayError):
        rail.execute(REQUEST, "h1", KEY)


def test_a_replayed_answer_for_this_key_is_this_certificates_own_transfer():
    rail, cassette = _rail(_replayed(_transfer()))
    payment = rail.execute(REQUEST, "h1", KEY)
    assert (payment.payment_id, payment.status, payment.idempotency_key) == (
        recorded("account_transfer")["body"]["id"],
        "complete",
        KEY,
    )
    assert len(cassette.requests) == 1


@pytest.mark.parametrize("lost", [LOST, (500, {"type": "internal_server_error"})])
def test_a_lost_answer_the_sdk_retries_into_a_replay_is_paid(lost):
    rail, cassette = _rail(lost, _replayed(_transfer()), max_retries=2)
    payment = rail.execute(REQUEST, "h1", KEY)
    assert payment.payment_id == recorded("account_transfer")["body"]["id"]
    assert (payment.amount_cents, payment.from_acct, payment.to_acct) == (
        20000,
        "checking-881",
        "acme-991",
    )
    sent = [
        (r.method, r.url.path, r.headers["idempotency-key"]) for r in cassette.requests
    ]
    assert sent == [("POST", "/account_transfers", KEY)] * 2


def test_the_recorded_replay_of_another_transfer_is_never_paid():
    rail, _ = _rail(LOST, "account_transfer_replayed", max_retries=2)
    with pytest.raises(RailError, match="^bank: transfer differs$"):
        rail.execute(REQUEST, "h1", KEY)


DIFFERENT = [
    {"amount": 19999},
    {"account_id": "account_other"},
    {"destination_account_id": "account_evil"},
    {"idempotency_key": "mandate-cert-other"},
    {"currency": "EUR"},
]


@pytest.mark.parametrize("change", DIFFERENT)
@pytest.mark.parametrize("replayed", [True, False])
def test_a_transfer_that_differs_from_the_request_is_never_paid(change, replayed):
    body = _transfer(**change)
    rail, _ = _rail(_replayed(body) if replayed else (200, body))
    with pytest.raises(RailError, match="^bank: transfer differs$"):
        rail.execute(REQUEST, "h1", KEY)


def test_a_replayed_transfer_left_pending_is_not_a_payment():
    rail, _ = _rail(
        LOST, _replayed(_transfer(status="pending_approval")), max_retries=1
    )
    with pytest.raises(RailError, match="^bank: not complete$"):
        rail.execute(REQUEST, "h1", KEY)


@pytest.mark.parametrize(
    "lost",
    [LOST, httpx.ConnectError("reset"), (503, {"type": "internal_server_error"})],
)
def test_no_answer_is_reconciled_by_one_lookup_of_the_key(lost):
    rail, cassette = _rail(lost, _listed(_transfer()))
    payment = rail.execute(REQUEST, "h1", KEY)
    assert payment.payment_id == recorded("account_transfer")["body"]["id"]
    lookup = cassette.requests[1]
    assert (lookup.method, lookup.url.path) == ("GET", "/account_transfers")
    assert dict(lookup.url.params) == {"idempotency_key": KEY}
    assert len(cassette.requests) == 2


def test_retries_that_all_lose_their_answer_end_in_the_lookup():
    rail, cassette = _rail(LOST, LOST, _listed(_transfer()), max_retries=1)
    assert rail.execute(REQUEST, "h1", KEY).status == "complete"
    assert [r.method for r in cassette.requests] == ["POST", "POST", "GET"]


@pytest.mark.parametrize(
    ("found", "reason"),
    [
        (_listed(), "bank: outcome unknown"),
        (LOST, "bank: outcome unknown"),
        ((500, {"type": "internal_server_error"}), "bank: outcome unknown"),
        (_listed(_transfer(status="pending_approval")), "bank: not complete"),
        (_listed(_transfer(amount=1)), "bank: transfer differs"),
    ],
)
def test_the_lookup_after_no_answer_never_guesses(found, reason):
    rail, cassette = _rail(LOST, found)
    with pytest.raises(RailError) as raised:
        rail.execute(REQUEST, "h1", KEY)
    assert str(raised.value) == reason
    assert len(cassette.requests) == 2


def test_reconcile_finds_the_transfer_by_its_key_or_nothing():
    rail, cassette = _rail(_listed(_transfer()), _listed())
    found = rail.reconcile(REQUEST, "h1", KEY)
    assert found is not None
    assert (found.payment_id, found.action_hash, found.idempotency_key) == (
        recorded("account_transfer")["body"]["id"],
        "h1",
        KEY,
    )
    assert rail.reconcile(REQUEST, "h1", KEY) is None
    assert [dict(r.url.params) for r in cassette.requests] == [
        {"idempotency_key": KEY}
    ] * 2


def test_bank_time_is_bounded():
    client = sandbox_client(SENTINEL_KEY)
    assert client.max_retries == 0
    assert client.timeout == httpx.Timeout(10.0, connect=5.0)
    rail, cassette = _rail((200, _transfer()))
    rail.execute(REQUEST, "h1", KEY)
    assert cassette.requests[0].extensions["timeout"] == {
        "connect": 5.0,
        "read": 10.0,
        "write": 10.0,
        "pool": 10.0,
    }


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
    rail, _ = _rail((200, _transfer(status="pending_approval")))
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
    transfer = dict(
        recorded("account_transfer")["body"], amount=20000, idempotency_key=KEY
    )
    cassette = Cassette((200, listed), (200, transfer))
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


def test_account_id_names_the_bank_id_of_a_demo_account():
    rail = IncreaseRail(Cassette().client(), {"checking-881": "account_payer"})
    assert rail.account_id("checking-881") == "account_payer"
    with pytest.raises(ValueError, match="^unknown account: acme-991$"):
        rail.account_id("acme-991")


HTML = httpx.Response(
    200, text="<html>ok</html>", headers={"content-type": "text/html"}
)
NOT_TRANSFERS = [
    pytest.param(HTML, id="html"),
    pytest.param(
        httpx.Response(
            200, content=b"not json", headers={"content-type": "application/json"}
        ),
        id="unparsable-json",
    ),
    pytest.param((200, []), id="json-list"),
    pytest.param(
        httpx.Response(302, headers={"location": "https://sandbox.increase.com/x"}),
        id="redirect",
    ),
    pytest.param(
        httpx.Response(
            400, text="<html>no</html>", headers={"content-type": "text/html"}
        ),
        id="unparsed-4xx",
    ),
]


@pytest.mark.parametrize("answer", NOT_TRANSFERS)
def test_an_answer_that_is_not_a_transfer_is_settled_by_the_lookup(answer):
    rail, cassette = _rail(answer, _listed(_transfer()))
    payment = rail.execute(REQUEST, "h1", KEY)
    assert payment.payment_id == recorded("account_transfer")["body"]["id"]
    assert [(r.method, r.url.path) for r in cassette.requests] == [
        ("POST", "/account_transfers"),
        ("GET", "/account_transfers"),
    ]
    assert dict(cassette.requests[1].url.params) == {"idempotency_key": KEY}


@pytest.mark.parametrize("answer", NOT_TRANSFERS)
def test_an_answer_that_is_not_a_transfer_with_nothing_found_is_unknown(answer):
    rail, cassette = _rail(answer, _listed())
    with pytest.raises(RailError, match="^bank: outcome unknown$"):
        rail.execute(REQUEST, "h1", KEY)
    assert len(cassette.requests) == 2


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(HTML, id="html"),
        pytest.param((200, []), id="json-list"),
        pytest.param((200, {"data": "x"}), id="data-not-a-list"),
        pytest.param((200, {"data": [1], "next_cursor": None}), id="not-a-transfer"),
        pytest.param(
            httpx.Response(302, headers={"location": "https://sandbox.increase.com/"}),
            id="redirect",
        ),
    ],
)
def test_a_lookup_answer_that_is_not_a_transfer_list_is_unknown(answer):
    rail, cassette = _rail(answer)
    with pytest.raises(RailError, match="^bank: outcome unknown$"):
        rail.reconcile(REQUEST, "h1", KEY)
    assert len(cassette.requests) == 1


def test_the_client_never_follows_a_redirect():
    assert sandbox_client(SENTINEL_KEY)._client.follow_redirects is False
    seen: list[httpx.Request] = []
    answers = iter(
        [
            httpx.Response(307, headers={"location": "https://elsewhere.example/t"}),
            HTML,
            httpx.Response(200, json={"data": [], "next_cursor": None}),
        ]
    )

    def answer(request):
        seen.append(request)
        return next(answers)

    following = httpx.Client(
        transport=httpx.MockTransport(answer), follow_redirects=True
    )
    rail = IncreaseRail(sandbox_client(SENTINEL_KEY, following), ACCOUNTS)
    with pytest.raises(RailError, match="^bank: outcome unknown$"):
        rail.execute(REQUEST, "h1", KEY)
    assert [(r.method, r.url.host, r.url.path) for r in seen] == [
        ("POST", "sandbox.increase.com", "/account_transfers"),
        ("GET", "sandbox.increase.com", "/account_transfers"),
    ]
