"""The bank's card authorizations under attack, on a served desk and webhook."""

import time
from typing import Any

import httpx2
import pytest

from bank.conftest import (
    AGENT_CARD_ID,
    CARD_ACCOUNT_ID,
    DECISION_ID,
    WEBHOOK_SECRET,
    Cassette,
    RecordingRail,
    decision_body,
    sign_webhook,
    webhook_event,
)
from conftest import DESK_NOW
from e2e.attack_world import approval_body, unsigned
from e2e.test_bank_attacks import BOUND, _sandbox, _tool
from gate.consent import sign_approval
from swarm.card import WEBHOOK_PATH, CardAuthorizer, card_webhook_app

READ = (200, decision_body())
APPROVE = (200, decision_body("responded", "approve"))
DECLINE = (200, decision_body("responded", "decline"))
QUOTE_ID = "q:000001"


class Card:
    """A served desk with one holder-approved quote, and its card webhook."""

    def __init__(self, make_desk, serve, state, answers, two_step=False) -> None:
        self.rail = RecordingRail(balance=50000, two_step=two_step)
        self.url, self.desk, holder = _sandbox(make_desk, serve, self.rail, state=state)
        quote = _tool(self.url, "quote_payment", BOUND)
        approved = httpx2.post(
            f"{self.url}/api/approve",
            json=approval_body(
                quote["quote_id"], sign_approval(holder, unsigned(quote))
            ),
        )
        assert approved.json()["status"] == "approved"
        self.cassette = Cassette(*answers)
        # The bank's deadline is read against the desk's own clock.
        authorizer = CardAuthorizer(
            self.cassette.client(),
            self.desk,
            AGENT_CARD_ID,
            CARD_ACCOUNT_ID,
            state,
            lambda: float(DESK_NOW),
        )
        app = card_webhook_app(self.cassette.client(), authorizer, WEBHOOK_SECRET)
        self.hook = serve(app) + WEBHOOK_PATH

    def send(self, body: bytes, headers: dict[str, str]) -> httpx2.Response:
        return httpx2.post(self.hook, content=body, headers=headers)

    def status(self) -> str:
        found = _tool(self.url, "get_payment_status", {"quote_id": QUOTE_ID})
        return str(found["status"])

    def sent(self) -> list[str]:
        return [r.method for r in self.cassette.requests]

    def approved_at_bank(self) -> bool:
        return any(b'"approve"' in r.content for r in self.cassette.requests)


def _honest(card: Card) -> None:
    body = webhook_event()
    answer = card.send(body, sign_webhook(body))
    assert (answer.status_code, answer.json()) == (200, {"status": "approved"})
    assert card.status() == "confirmed"
    assert card.approved_at_bank()


def _forged(case: str) -> tuple[bytes, dict[str, str]]:
    body = webhook_event()
    now = int(time.time())
    if case == "unsigned":
        return body, {}
    if case == "another secret":
        return body, sign_webhook(body, secret="mallory_secret")  # noqa: S106
    if case == "stale":
        return body, sign_webhook(body, timestamp=now - 600)
    if case == "future":
        return body, sign_webhook(body, timestamp=now + 600)
    if case == "edited body":
        edited = webhook_event("sandbox_real_time_decision_mallory0000000000")
        return edited, sign_webhook(body)
    signed = webhook_event(category="account_transfer.created")
    return signed, sign_webhook(signed)


@pytest.mark.parametrize(
    ("case", "want"),
    [
        ("unsigned", (401, {"error": "webhook: unsigned"})),
        ("another secret", (401, {"error": "webhook: bad signature"})),
        ("stale", (401, {"error": "webhook: bad signature"})),
        ("future", (401, {"error": "webhook: bad signature"})),
        ("edited body", (401, {"error": "webhook: bad signature"})),
        ("not a card", (400, {"error": "webhook: not a card authorization"})),
    ],
)
def test_a_webhook_the_bank_did_not_sign_reads_nothing(
    make_desk, serve, state_store, case, want
):
    card = Card(make_desk, serve, state_store, (READ, APPROVE))
    answer = card.send(*_forged(case))
    assert (answer.status_code, answer.json()) == want
    assert (card.sent(), card.status()) == ([], "approved")
    _honest(card)


def test_a_replayed_webhook_is_answered_once(make_desk, serve, state_store):
    card = Card(make_desk, serve, state_store, (READ, APPROVE))
    body = webhook_event()
    headers = sign_webhook(body)
    assert card.send(body, headers).json() == {"status": "approved"}
    again = card.send(body, headers)
    redelivered = card.send(body, sign_webhook(body, msg_id="msg_2"))
    assert [again.json(), redelivered.json()] == [{"status": "duplicate"}] * 2
    assert card.sent() == ["GET", "POST"]
    assert card.rail.calls == []


@pytest.mark.parametrize(
    "change",
    [
        {"settlement_amount": 30000, "presentment_amount": 30000},
        {"merchant_acceptor_id": "mallory-1"},
        {"card_id": "card_mallory"},
    ],
    ids=["bigger amount", "another merchant", "another card"],
)
def test_a_decision_for_another_payment_is_never_approved(
    make_desk, serve, state_store, change
):
    card = Card(
        make_desk, serve, state_store, ((200, decision_body(**change)), DECLINE)
    )
    body = webhook_event()
    answer = card.send(body, sign_webhook(body))
    assert answer.json() == {"status": "declined"}
    assert (card.sent(), card.approved_at_bank()) == (["GET", "POST"], False)
    assert card.status() == "approved"


def test_a_decision_past_its_deadline_is_never_approved(make_desk, serve, state_store):
    late = (200, decision_body(timeout_at="2027-01-15T08:16:40Z"))
    card = Card(make_desk, serve, state_store, (late,))
    body = webhook_event()
    assert card.send(body, sign_webhook(body)).json() == {"status": "not_answered"}
    assert card.sent() == ["GET"]
    assert card.status() == "approved"


def test_a_card_spends_the_quote_and_the_agent_cannot_pay_it_again(
    make_desk, serve, state_store
):
    card = Card(make_desk, serve, state_store, (READ, APPROVE))
    _honest(card)
    paid: dict[str, Any] = _tool(card.url, "confirm_payment", {"quote_id": QUOTE_ID})
    assert (paid["status"], paid["payment_id"]) == ("confirmed", DECISION_ID)
    assert card.rail.calls == []


def test_a_quote_the_agent_paid_is_never_spent_by_card(make_desk, serve, state_store):
    card = Card(make_desk, serve, state_store, (READ, DECLINE))
    paid = _tool(card.url, "confirm_payment", {"quote_id": QUOTE_ID})
    assert paid["payment_id"] == card.rail.paid_id
    body = webhook_event()
    assert card.send(body, sign_webhook(body)).json() == {"status": "declined"}
    assert (card.sent(), card.approved_at_bank()) == (["GET", "POST"], False)
    assert len(card.rail.calls) == 1


def test_a_card_on_a_two_step_desk_is_never_approved(make_desk, serve, state_store):
    card = Card(make_desk, serve, state_store, (READ, DECLINE), two_step=True)
    body = webhook_event()
    assert card.send(body, sign_webhook(body)).json() == {"status": "declined"}
    assert (card.sent(), card.approved_at_bank()) == (["GET", "POST"], False)
    assert card.status() == "approved"
    assert (len(card.rail.holds), card.rail.calls) == (1, [])
