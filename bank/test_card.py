import json
import os
import time

import httpx
import pytest

from bank import card, increase
from bank.api import Payment, PaymentRequest, RailError
from bank.card import (
    AGENT_CARD,
    CARD_CATEGORY,
    CARD_SAFETY_S,
    CardAuthorization,
    CardDecisionRail,
    CardWebhookError,
    agent_card,
    charge_cli,
    decline,
    ensure_card,
    ensure_card_subscription,
    read_authorization,
    webhook_decision_id,
)
from bank.conftest import (
    AGENT_CARD_ID,
    CARD_ACCOUNT_ID,
    DECISION_ID,
    SENTINEL_KEY,
    WEBHOOK_SECRET,
    Cassette,
    decision_body,
    named_accounts,
    page,
    recorded,
    sign_webhook,
    webhook_event,
)
from bank.credentials import BANK_KEY_ENV, WEBHOOK_SECRET_ENV
from bank.increase import setup_cli

# Derived outside the code with standardwebhooks 1.1.0 Webhook.sign over this
# body, secret bytes, id and timestamp, and again with stdlib hmac/sha256.
KAV_BODY = (
    '{"id":"event_001","type":"event","category":"real_time_decision.card_'
    'authorization_requested","associated_object_type":"real_time_decision'
    '","associated_object_id":"real_time_decision_j76n2e810ezcg3zh5qtn","c'
    'reated_at":"2020-01-31T23:59:59Z"}'
)


def _decide(body, headers):
    return webhook_decision_id(Cassette().client(), body, headers, WEBHOOK_SECRET)


KAV_ID = "msg_2pxW4cBxKBsIezP0w9ewxI1QLbF"


def test_the_test_signer_is_standard_webhooks():
    assert webhook_event().decode() == KAV_BODY
    assert sign_webhook(KAV_BODY, KAV_ID, 1800001000) == {
        "webhook-id": KAV_ID,
        "webhook-timestamp": "1800001000",
        "webhook-signature": "v1,j1CKyQ8xFu2zW4DlJKg4mwAYv3dKV+JhHE7LdzD81U4=",
    }


def test_a_signed_card_authorization_names_its_decision():
    body = webhook_event()
    headers = {k.upper(): v for k, v in sign_webhook(body).items()}
    assert _decide(body, headers) == DECISION_ID


def _unverified(case):
    body = webhook_event()
    good = sign_webhook(body)
    now = int(time.time())
    if case == "unsigned":
        return body, {k: v for k, v in good.items() if k != "webhook-signature"}
    if case == "wrong secret":
        return body, sign_webhook(body, secret="another_secret")  # noqa: S106
    if case == "tampered":
        return body.replace(b"j76n", b"j77n"), good
    if case == "stale":
        return body, sign_webhook(body, timestamp=now - 301)
    if case == "future":
        return body, sign_webhook(body, timestamp=now + 301)
    if case == "no comma":
        return body, dict(good, **{"webhook-signature": "garbage"})
    if case == "not utf-8":
        return b"\xff\xfe", sign_webhook(b"\xff\xfe")
    return body, dict(good, **{"webhook-signature": good["webhook-signature"][3:]})


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("unsigned", "webhook: unsigned"),
        ("wrong secret", "webhook: bad signature"),
        ("tampered", "webhook: bad signature"),
        ("stale", "webhook: bad signature"),
        ("future", "webhook: bad signature"),
        ("no comma", "webhook: bad signature"),
        ("not utf-8", "webhook: bad signature"),
        ("no version", "webhook: bad signature"),
    ],
)
def test_unverified_webhooks_name_no_decision(case, reason):
    body, headers = _unverified(case)
    with pytest.raises(CardWebhookError, match=f"^{reason}$"):
        _decide(body, headers)


@pytest.mark.parametrize(
    "body",
    [
        webhook_event(category="account_transfer.created"),
        webhook_event(object_type="account"),
        webhook_event("real_time_decision_../x"),
        webhook_event("card_oubs0hwk5rn6knuecxg2"),
        b"[1]",
    ],
)
def test_verified_events_that_are_not_card_authorizations_are_refused(body):
    with pytest.raises(CardWebhookError, match="^webhook: not a card authorization$"):
        _decide(body, sign_webhook(body))


T0 = 1800001000.0
DEADLINE = 1800001004.0  # 2027-01-15T08:16:44Z, by time.gmtime outside the code
REQUEST = PaymentRequest("checking-881", "acme-991", 20000, "USD", "A-991")
KEY = "mandate-cert-" + "c1" * 16
URL = "https://sandbox.increase.com/real_time_decisions/" + DECISION_ID
APPROVED = (200, decision_body("responded", "approve"))
ERROR_409 = (409, {"status": 409, "type": "invalid_operation_error", "title": "x"})
ERROR_401 = (401, {"status": 401, "type": "invalid_api_key_error", "title": "x"})
HTML_429 = httpx.Response(429, text="<html>slow down</html>")
OTHER_APPROVED = (
    200,
    {**decision_body("responded", "approve"), "id": "real_time_decision_other"},
)
LOST = httpx.ReadTimeout("lost")
DOWN = httpx.ConnectError("down")


def _read(body):
    client = Cassette((200, body)).client()
    return read_authorization(client.real_time_decisions.retrieve(DECISION_ID))


def _rail(*answers, now=T0, retries=0, **card):
    cassette = Cassette(*answers)
    auth = _read(decision_body(**card))
    rail = CardDecisionRail(
        cassette.client(max_retries=retries),
        auth,
        "checking-881",
        CARD_ACCOUNT_ID,
        DEADLINE,
        lambda: now,
        card_id=AGENT_CARD_ID,
    )
    return rail, cassette


def _total(request):
    return sum(request.extensions["timeout"].values())


def test_a_pending_purchase_reads_field_by_field():
    assert _read(decision_body()) == CardAuthorization(
        DECISION_ID,
        "account_checking-881",
        "card_agent",
        20000,
        "USD",
        "acme-991",
        "ACME 991",
        DEADLINE,
    )


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"status": "responded"}, "card: not pending"),
        ({"status": "timed_out"}, "card: not pending"),
        ({"direction": "refund"}, "card: not a purchase"),
        ({"processing_category": "cash_disbursement"}, "card: not a purchase"),
        ({"category": "card_balance_inquiry_requested"}, "card: not a purchase"),
        # The SDK turns "20000" into 20000; a fractional string it keeps.
        ({"settlement_amount": "20000.5"}, "card: malformed decision"),
        ({"settlement_amount": 0}, "card: malformed decision"),
        ({"timeout_at": "2027-01-15T08:16:44"}, "card: malformed decision"),
        ({"card_authorization": None}, "card: malformed decision"),
        ({"id": 7}, "card: malformed decision"),
    ],
)
def test_only_a_pending_purchase_reads_as_a_card_authorization(change, reason):
    body = decision_body()
    top = {k: v for k, v in change.items() if k in body}
    body = decision_body(**{k: v for k, v in change.items() if k not in body})
    body.update(top)
    with pytest.raises(ValueError, match=f"^{reason}$"):
        _read(body)


def test_anything_but_a_decision_is_malformed():
    with pytest.raises(ValueError, match="^card: malformed decision$"):
        read_authorization({"id": DECISION_ID})


def test_approval_is_one_keyed_action_and_the_decision_is_the_payment():
    rail, cassette = _rail(APPROVED)
    payment = rail.execute(REQUEST, "h1", KEY)
    [sent] = cassette.requests
    assert (sent.method, str(sent.url)) == ("POST", URL + "/action")
    assert sent.headers["idempotency-key"] == KEY
    assert json.loads(sent.content) == {"card_authorization": {"decision": "approve"}}
    assert _total(sent) == pytest.approx(DEADLINE - CARD_SAFETY_S - T0)
    assert payment == Payment(
        DECISION_ID,
        "checking-881",
        "acme-991",
        20000,
        "USD",
        "A-991",
        "h1",
        rail="sandbox",
        provider="increase",
        status="approved",
        idempotency_key=KEY,
    )


@pytest.mark.parametrize(
    "card",
    [
        {"settlement_amount": 19999},
        {"merchant_acceptor_id": "evil-666"},
        {"settlement_currency": "EUR"},
        {"account_id": "account_other"},
        {"card_id": "card_other"},
    ],
)
def test_the_rail_refuses_an_authorization_that_differs(card):
    rail, cassette = _rail(**card)
    with pytest.raises(RailError, match="^card: authorization differs$"):
        rail.execute(REQUEST, "h1", KEY)
    assert cassette.requests == []


@pytest.mark.parametrize(("now", "sent"), [(1800001003.5, 0), (1800001003.4, 1)])
def test_no_approval_starts_after_the_safety_margin(now, sent):
    rail, cassette = _rail(APPROVED, now=now)
    if sent:
        assert rail.execute(REQUEST, "h1", KEY).status == "approved"
    else:
        with pytest.raises(RailError, match="^card: deadline passed$"):
            rail.execute(REQUEST, "h1", KEY)
    assert len(cassette.requests) == sent


@pytest.mark.parametrize(
    ("answers", "outcome"),
    [
        ((LOST, APPROVED), "approved"),
        ((ERROR_409, (200, decision_body("timed_out"))), "card: deadline passed"),
        (
            ((200, decision_body("responded", "decline")),) * 2,
            "card: declined at the bank",
        ),
        ((LOST, (200, decision_body())), "bank: outcome unknown"),
        ((LOST, DOWN), "bank: outcome unknown"),
        ((ERROR_401,), "bank: unavailable"),
        ((HTML_429, APPROVED), "approved"),
        ((OTHER_APPROVED, (200, decision_body("timed_out"))), "card: deadline passed"),
    ],
)
def test_a_lost_approval_is_settled_by_one_read(answers, outcome):
    rail, cassette = _rail(*answers)
    if outcome == "approved":
        assert rail.execute(REQUEST, "h1", KEY).payment_id == DECISION_ID
    else:
        with pytest.raises(RailError, match=f"^{outcome}$"):
            rail.execute(REQUEST, "h1", KEY)
    reads = [(r.method, str(r.url)) for r in cassette.requests[1:]]
    assert reads == [("GET", URL)] * (len(answers) - 1)
    if reads:
        assert cassette.requests[1].extensions["timeout"]["read"] == 2.0


def test_a_card_decision_is_never_looked_up_as_a_transfer():
    rail, cassette = _rail()
    with pytest.raises(RailError, match="^bank: outcome unknown$"):
        rail.reconcile(REQUEST, "h1", KEY)
    assert cassette.requests == []


def test_decline_is_one_keyed_action_and_never_late():
    cassette = Cassette((200, decision_body("responded", "decline")))
    assert decline(cassette.client(), DECISION_ID, DEADLINE, lambda: T0 + 1) is True
    [sent] = cassette.requests
    assert sent.headers["idempotency-key"] == "mandate-decline-" + DECISION_ID
    assert json.loads(sent.content) == {
        "card_authorization": {
            "decision": "decline",
            "decline": {"reason": "transaction_never_allowed"},
        }
    }
    late = Cassette()
    assert decline(late.client(), DECISION_ID, DEADLINE, lambda: DEADLINE) is False
    assert late.requests == []
    down = Cassette(DOWN)
    assert decline(down.client(), DECISION_ID, DEADLINE, lambda: T0) is False


@pytest.mark.parametrize(("now", "total"), [(T0, 3.5), (1800001003.4, 0.1)])
def test_the_whole_approve_call_ends_before_the_safety_margin(now, total):
    rail, cassette = _rail(APPROVED, now=now)
    rail.execute(REQUEST, "h1", KEY)
    [sent] = cassette.requests
    timeout = sent.extensions["timeout"]
    assert all(v > 0 for v in timeout.values())
    assert _total(sent) == pytest.approx(total)


@pytest.mark.parametrize(("now", "sent"), [(T0, 1), (T0 + 1.5, 0)])
def test_the_rail_never_outlasts_the_banks_own_deadline(now, sent):
    early = "2027-01-15T08:16:42Z"  # two seconds before the rail's deadline
    rail, cassette = _rail(APPROVED, now=now, timeout_at=early)
    if sent:
        rail.execute(REQUEST, "h1", KEY)
        assert _total(cassette.requests[0]) == pytest.approx(1.5)
    else:
        with pytest.raises(RailError, match="^card: deadline passed$"):
            rail.execute(REQUEST, "h1", KEY)
    assert len(cassette.requests) == sent


def test_a_lost_approval_is_never_resent_by_the_client():
    rail, cassette = _rail(LOST, APPROVED, retries=2)
    assert rail.execute(REQUEST, "h1", KEY).status == "approved"
    assert [r.method for r in cassette.requests] == ["POST", "GET"]


@pytest.mark.parametrize("key", [None, "", "mandate-cert-", "other-c1c1"])
def test_an_approval_needs_the_certificate_key(key):
    rail, cassette = _rail(APPROVED)
    with pytest.raises(ValueError, match="^card decisions need a certificate key$"):
        rail.execute(REQUEST, "h1", key)
    assert cassette.requests == []


def test_a_decline_is_never_resent_and_ends_by_the_deadline():
    cassette = Cassette(LOST, (200, decision_body("responded", "decline")))
    client = cassette.client(max_retries=2)
    assert decline(client, DECISION_ID, DEADLINE, lambda: T0 + 1) is False
    [sent] = cassette.requests
    assert _total(sent) == pytest.approx(3.0)


@pytest.mark.parametrize("bad_first", [True, False])
def test_two_differing_signature_headers_never_verify(bad_first):
    body = webhook_event()
    good = sign_webhook(body)
    bad = sign_webhook(body, secret="another_secret")["webhook-signature"]  # noqa: S106
    pair = [
        ("Webhook-Signature", bad),
        ("webhook-signature", good["webhook-signature"]),
    ]
    if not bad_first:
        pair = [(pair[0][0], pair[1][1]), (pair[1][0], pair[0][1])]
    headers = {k: v for k, v in good.items() if k != "webhook-signature"}
    headers.update(pair)
    with pytest.raises(CardWebhookError, match="^webhook: bad signature$"):
        _decide(body, headers)


def test_the_same_signature_header_twice_still_verifies():
    body = webhook_event()
    headers = sign_webhook(body)
    headers["WEBHOOK-SIGNATURE"] = headers["webhook-signature"]
    assert _decide(body, headers) == DECISION_ID


HOOK_URL = "https://mandate-demo.trycloudflare.com/increase/card-authorizations"


def _card(**change):
    return dict(recorded("card")["body"], **change)


def _sub(url, status="active"):
    return dict(
        recorded("event_subscription")["body"],
        id="event_subscription_old",
        url=url,
        status=status,
        selected_event_categories=[{"event_category": CARD_CATEGORY}],
    )


def test_setup_opens_one_agent_card_and_points_one_subscription():
    cassette = Cassette(
        page(),
        (200, _card(id="card_new", description=AGENT_CARD)),
        page(_sub("https://old.example/hook")),
        (200, _sub("https://old.example/hook", "deleted")),
        (200, _sub(HOOK_URL)),
    )
    client = cassette.client()
    assert ensure_card(client, CARD_ACCOUNT_ID, "checking-881") == "card_new"
    ensure_card_subscription(client, HOOK_URL, WEBHOOK_SECRET)
    sent = [(r.method, r.url.path) for r in cassette.requests]
    assert sent == [
        ("GET", "/cards"),
        ("POST", "/cards"),
        ("GET", "/event_subscriptions"),
        ("PATCH", "/event_subscriptions/event_subscription_old"),
        ("POST", "/event_subscriptions"),
    ]
    create_card, delete, create_sub = (cassette.requests[i] for i in (1, 3, 4))
    assert create_card.headers["idempotency-key"] == "mandate-setup-card-checking-881"
    assert json.loads(create_card.content) == {
        "account_id": CARD_ACCOUNT_ID,
        "description": "mandate-agent-card",
    }
    assert json.loads(delete.content) == {"status": "deleted"}
    assert json.loads(create_sub.content) == {
        "url": HOOK_URL,
        "selected_event_categories": [{"event_category": CARD_CATEGORY}],
        "shared_secret": WEBHOOK_SECRET,
    }


def test_setup_reuses_the_card_and_the_subscription_it_finds():
    cassette = Cassette(
        page(_card(id="card_old", status="active", description=AGENT_CARD)),
        page(_sub(HOOK_URL)),
    )
    client = cassette.client()
    assert ensure_card(client, CARD_ACCOUNT_ID, "checking-881") == "card_old"
    ensure_card_subscription(client, HOOK_URL, WEBHOOK_SECRET)
    assert [r.method for r in cassette.requests] == ["GET", "GET"]


def test_only_an_active_agent_card_is_the_agent_card():
    cards = page(
        _card(id="card_1", status="canceled", description=AGENT_CARD),
        _card(id="card_2", status="active", description="someone else"),
    )
    assert agent_card(Cassette(cards).client(), CARD_ACCOUNT_ID) is None


def test_setup_refuses_a_plain_http_webhook_url(monkeypatch, capsys):
    monkeypatch.setenv(BANK_KEY_ENV, "k")
    with pytest.raises(SystemExit) as stopped:
        setup_cli(["--card-webhook-url", "http://mandate-demo.example/hook"])
    assert stopped.value.code == 2
    assert capsys.readouterr().err == "card webhook URL must be https\n"


@pytest.mark.parametrize(
    ("answer", "printed"),
    [
        (
            "card_authorization_simulation",
            "approved ({})".format(
                recorded("card_authorization_simulation")["body"][
                    "pending_transaction"
                ]["id"]
            ),
        ),
        ("card_authorization_declined", "declined (webhook_declined)"),
    ],
)
def test_the_merchant_stand_in_charges_the_agent_card(
    monkeypatch, capsys, answer, printed
):
    agent = _card(id="card_agent", status="active", description=AGENT_CARD)
    cassette = Cassette(named_accounts("checking-881", "acme-991"), page(agent), answer)
    monkeypatch.setenv(BANK_KEY_ENV, "k")
    monkeypatch.setattr(card, "sandbox_client", lambda key: cassette.client())
    charge_cli(["--amount-cents", "20000"])
    charge = cassette.requests[-1]
    assert charge.url.path == "/simulations/card_authorizations"
    assert json.loads(charge.content) == {
        "amount": 20000,
        "card_id": "card_agent",
        "merchant_acceptor_id": "acme-991",
        "merchant_descriptor": "ACME 991",
    }
    assert capsys.readouterr().out == f"Card authorization at acme-991: {printed}\n"
    assert BANK_KEY_ENV not in os.environ


def test_the_merchant_stand_in_takes_the_webhook_secret_out_of_its_environment(
    monkeypatch, capsys
):
    agent = _card(id="card_agent", status="active", description=AGENT_CARD)
    cassette = Cassette(
        named_accounts("checking-881", "acme-991"),
        page(agent),
        "card_authorization_declined",
    )
    monkeypatch.setenv(BANK_KEY_ENV, "k")
    monkeypatch.setenv(WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    monkeypatch.setenv("INCREASE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    monkeypatch.setattr(card, "sandbox_client", lambda key: cassette.client())
    charge_cli(["--amount-cents", "20000"])
    assert WEBHOOK_SECRET_ENV not in os.environ
    assert "INCREASE_WEBHOOK_SECRET" not in os.environ
    assert WEBHOOK_SECRET not in capsys.readouterr().out


def test_the_merchant_stand_in_says_when_the_sandbox_is_unreachable(
    monkeypatch, capsys
):
    cassette = Cassette(httpx.ConnectError("down"))
    monkeypatch.setenv(BANK_KEY_ENV, "k")
    monkeypatch.setattr(card, "sandbox_client", lambda key: cassette.client())
    with pytest.raises(SystemExit) as stopped:
        charge_cli(["--amount-cents", "20000"])
    assert stopped.value.code == 2
    assert capsys.readouterr().err == (
        "bank rail unavailable: the sandbox is unreachable\n"
    )


def test_setup_needs_the_webhook_secret_for_a_card_url(monkeypatch, capsys):
    monkeypatch.setenv(BANK_KEY_ENV, "k")
    monkeypatch.delenv(WEBHOOK_SECRET_ENV, raising=False)
    with pytest.raises(SystemExit) as stopped:
        setup_cli(["--card-webhook-url", HOOK_URL])
    assert stopped.value.code == 2
    assert capsys.readouterr().err == (
        "card webhook unavailable: set INCREASE_SANDBOX_WEBHOOK_SECRET\n"
    )


def test_setup_points_the_card_at_the_url_and_keeps_the_secret(monkeypatch, capsys):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    monkeypatch.setenv(WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    available = recorded("balance_lookup")["body"]["available_balance"]
    listed = named_accounts("checking-881", "acme-991")
    agent = _card(id="card_agent", status="active", description=AGENT_CARD)
    cassette = Cassette(
        listed, "balance_lookup", page(agent), page(), (200, _sub(HOOK_URL)),
        listed, "balance_lookup",
    )  # fmt: skip
    monkeypatch.setattr(increase, "sandbox_client", lambda key: cassette.client())
    setup_cli(["--fund-cents", str(available), "--card-webhook-url", HOOK_URL])
    out = capsys.readouterr().out
    assert out.splitlines()[2:] == [
        "Agent card ready: card_agent on checking-881",
        f"Card authorizations go to {HOOK_URL}",
    ]
    assert cassette.requests[2].url.params["account_id"] == "account_checking-881"
    assert json.loads(cassette.requests[4].content)["shared_secret"] == WEBHOOK_SECRET
    assert WEBHOOK_SECRET not in out
    assert WEBHOOK_SECRET_ENV not in os.environ
