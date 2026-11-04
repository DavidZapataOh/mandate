import itertools
import logging
import threading

import httpx
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
from bank.verifier import Verifier
from conftest import DESK_NOW
from gate.certs import generate_keypair
from gate.state import StateStore
from swarm.card import (
    WEBHOOK_PATH,
    CardAuthorizer,
    CardOutcome,
    card_webhook_app,
    card_webhook_server,
)
from swarm.conftest import DEMO_INTENT
from swarm.desk import PaymentDesk
from swarm.intent import sign_intent
from swarm.test_server import _asgi

OTHER = "real_time_decision_k2second0000000000"
BASE = "https://sandbox.increase.com/real_time_decisions/"
READ = (200, decision_body())
APPROVE = (200, decision_body("responded", "approve"))
DECLINE = (200, decision_body("responded", "decline"))


class Clock:
    """Test time: moves only when a test moves it."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _desk(state, clock, sign_quote, gate_s=0.0, publish=None, approve=True):
    gate_priv, gate_pub = generate_keypair()
    holder_priv, holder_pub = generate_keypair()
    counter = itertools.count(1)

    def salts():
        clock.now += gate_s  # the gate run takes gate_s seconds
        return b"\x05" * 32

    desk = PaymentDesk(
        source="checking-881",
        bank=RecordingRail(balance=50000),
        verifier=Verifier(gate_pub, state=state),
        gate_key=gate_priv,
        clock=lambda: int(clock.now),
        nonces=lambda: f"{next(counter):032x}",
        publish=publish,
        action_salts=salts,
        state=state,
    )
    desk.register_holder(holder_pub)
    desk.record_intent(DEMO_INTENT, sign_intent(holder_priv, DEMO_INTENT))
    quoted = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    if approve:
        desk.approve(quoted["quote_id"], sign_quote(holder_priv, quoted))
    return desk


def _authorizer(
    state, sign_quote, *answers, gate_s=0.0, publish=None, approve=True, wall=None
):
    clock = Clock(float(DESK_NOW))
    desk = _desk(state, clock, sign_quote, gate_s, publish, approve)
    cassette = Cassette(*answers)
    # The test clock never goes backwards, so it is also the monotonic one.
    authorizer = CardAuthorizer(
        cassette.client(),
        desk,
        AGENT_CARD_ID,
        CARD_ACCOUNT_ID,
        state,
        clock if wall is None else wall,
        monotonic=clock,
    )
    return authorizer, cassette


def _sent(cassette):
    return [(r.method, str(r.url).removeprefix(BASE)) for r in cassette.requests]


def test_certified_spend_approves_uncertified_declines_with_reason(
    state_store, sign_quote
):
    authorizer, cassette = _authorizer(
        state_store, sign_quote, READ, APPROVE, (200, dict(decision_body(), id=OTHER)),
        (200, dict(decision_body("responded", "decline"), id=OTHER)),
    )  # fmt: skip
    assert authorizer.handle(DECISION_ID) == CardOutcome(
        DECISION_ID, "approved", "ok: executed", "q:000001", True
    )
    assert authorizer.handle(OTHER) == CardOutcome(
        OTHER, "declined", "card: no approved quote", None, False
    )
    assert _sent(cassette) == [
        ("GET", DECISION_ID),
        ("POST", DECISION_ID + "/action"),
        ("GET", OTHER),
        ("POST", OTHER + "/action"),
    ]


def test_an_unapproved_quote_is_declined(state_store, sign_quote):
    authorizer, cassette = _authorizer(
        state_store, sign_quote, READ, DECLINE, approve=False
    )
    assert authorizer.handle(DECISION_ID).reason == "card: no approved quote"
    assert len(cassette.requests) == 2


def test_another_card_is_declined(state_store, sign_quote):
    other = (200, decision_body(card_id="card_other"))
    authorizer, cassette = _authorizer(state_store, sign_quote, other, DECLINE)
    outcome = authorizer.handle(DECISION_ID)
    assert (outcome.status, outcome.reason) == ("declined", "card: not the agent card")
    assert [m for m, _ in _sent(cassette)] == ["GET", "POST"]
    assert b'"decline"' in cassette.requests[1].content


@pytest.mark.parametrize(
    ("gate_s", "status", "sent"),
    [(3.7, "declined", 2), (4.2, "not_answered", 1)],
)
def test_a_slow_gate_never_approves(state_store, sign_quote, gate_s, status, sent):
    authorizer, cassette = _authorizer(
        state_store, sign_quote, READ, DECLINE, gate_s=gate_s
    )
    size = authorizer._desk.registry.size()
    outcome = authorizer.handle(DECISION_ID)
    assert (outcome.status, outcome.reason, outcome.sealed) == (
        status,
        "card: desk busy",
        False,
    )
    assert [m for m, _ in _sent(cassette)] == ["GET", "POST"][:sent]
    if sent == 2:
        assert b'"decline"' in cassette.requests[1].content
    # The holder's approval survives: only the card answer's denial is sealed.
    assert authorizer._desk.status("q:000001")["status"] == "approved"
    assert authorizer._desk.registry.size() == size + 1


@pytest.mark.parametrize(
    ("advance", "gate_s"),
    [(3.24, 0.05), (3.3, 0.0)],
    ids=["10 ms before the wait ends", "after the allowance"],
)
def test_a_lock_freed_too_late_keeps_the_quote(
    state_store, sign_quote, advance, gate_s
):
    authorizer, cassette = _authorizer(
        state_store, sign_quote, READ, DECLINE, gate_s=gate_s
    )
    desk = authorizer._desk
    clock = authorizer._monotonic
    held = threading.Event()

    def agent_payment():
        with desk._lock:
            held.set()
            threading.Event().wait(0.05)
            clock.now += advance  # the payment took this long, in desk time

    payer = threading.Thread(target=agent_payment)
    size = desk.registry.size()
    found = desk.card_quote

    def match_then_pay(*args, **kwargs):
        quote_id = found(*args, **kwargs)
        payer.start()
        held.wait(5)
        return quote_id

    desk.card_quote = match_then_pay
    outcome = authorizer.handle(DECISION_ID)
    payer.join(5)
    assert (outcome.status, outcome.reason, outcome.sealed) == (
        "declined",
        "card: desk busy",
        False,
    )
    assert desk.status("q:000001")["status"] == "approved"
    assert state_store.records("pending") == []
    assert desk.registry.size() == size + 1
    assert [m for m, _ in _sent(cassette)] == ["GET", "POST"]
    assert b'"approve"' not in b"".join(r.content for r in cassette.requests)


def test_a_decision_cannot_buy_time_with_a_late_timeout(state_store, sign_quote):
    late = (200, decision_body(timeout_at="2027-01-15T08:20:00Z"))
    authorizer, cassette = _authorizer(
        state_store, sign_quote, late, DECLINE, gate_s=3.7
    )
    assert authorizer.handle(DECISION_ID).reason == "card: desk busy"
    assert authorizer._desk.status("q:000001")["status"] == "approved"
    assert b'"approve"' not in b"".join(r.content for r in cassette.requests)


def test_a_replayed_decision_is_decided_once(state_store, sign_quote):
    authorizer, cassette = _authorizer(state_store, sign_quote, READ, APPROVE)
    assert authorizer.handle(DECISION_ID).status == "approved"
    assert authorizer.handle(DECISION_ID) is None
    assert len(cassette.requests) == 2


@pytest.mark.parametrize(
    ("answers", "status", "reason", "sent"),
    [
        ((httpx.ConnectError("down"), DECLINE), "declined", "card: unreadable", 2),
        (((200, decision_body("timed_out")),), "not_answered", "card: not pending", 1),
        (((200, decision_body(direction="refund")), DECLINE), "declined",
         "card: not a purchase", 2),
    ],
)  # fmt: skip
def test_a_decision_mandate_cannot_use_is_never_approved(
    state_store, sign_quote, answers, status, reason, sent
):
    authorizer, cassette = _authorizer(state_store, sign_quote, *answers)
    outcome = authorizer.handle(DECISION_ID)
    assert (outcome.status, outcome.reason) == (status, reason)
    assert len(cassette.requests) == sent


def test_a_lost_approval_is_an_unknown_answer(state_store, sign_quote):
    lost = (httpx.ReadTimeout("lost"), httpx.ConnectError("down"))
    authorizer, cassette = _authorizer(state_store, sign_quote, READ, *lost)
    outcome = authorizer.handle(DECISION_ID)
    assert (outcome.status, outcome.reason) == ("unknown", "bank: outcome unknown")
    assert [m for m, _ in _sent(cassette)] == ["GET", "POST", "GET"]


def test_every_answer_is_one_card_line(state_store, sign_quote):
    lines = []
    authorizer, _ = _authorizer(
        state_store, sign_quote, READ, APPROVE, publish=lines.append
    )
    authorizer.handle(DECISION_ID)
    assert [line.subject["step"] for line in lines[-2:]] == ["confirm", "card"]
    assert lines[-1].subject == {
        "step": "card",
        "quote_id": "q:000001",
        "status": "approved",
        "summary": "Card 200.00 USD at ACME 991 (acme-991) from checking-881",
        "payment_id": DECISION_ID,
        "reason": "ok: executed",
    }


@pytest.mark.anyio
async def test_a_signed_webhook_is_answered_after_the_bank_action(
    state_store, sign_quote
):
    authorizer, cassette = _authorizer(state_store, sign_quote, READ, APPROVE)
    app = card_webhook_app(cassette.client(), authorizer, WEBHOOK_SECRET)
    body = webhook_event()
    headers = sign_webhook(body)
    async with _asgi(app) as http:
        answer = await http.post(WEBHOOK_PATH, content=body, headers=headers)
    assert (answer.status_code, answer.json()) == (200, {"status": "approved"})
    assert len(cassette.requests) == 2


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("case", "status", "error"),
    [
        ("unsigned", 401, "webhook: unsigned"),
        ("forged", 401, "webhook: bad signature"),
        ("not a card", 400, "webhook: not a card authorization"),
        ("too large", 413, "webhook: too large"),
        ("get", 405, None),
    ],
)
async def test_unverified_webhooks_touch_nothing(
    state_store, sign_quote, case, status, error
):
    authorizer, cassette = _authorizer(state_store, sign_quote)
    app = card_webhook_app(cassette.client(), authorizer, WEBHOOK_SECRET)
    body = webhook_event()
    headers = sign_webhook(body)
    if case == "unsigned":
        headers = {}
    elif case == "forged":
        headers = sign_webhook(body, secret="another_secret")  # noqa: S106
    elif case == "not a card":
        body = webhook_event(category="account_transfer.created")
        headers = sign_webhook(body)
    elif case == "too large":
        body = b"x" * 16_385
    async with _asgi(app) as http:
        if case == "get":
            answer = await http.get(WEBHOOK_PATH)
        else:
            answer = await http.post(WEBHOOK_PATH, content=body, headers=headers)
    assert answer.status_code == status
    if error is not None:
        assert answer.json() == {"error": error}
    assert cassette.requests == []


def test_a_stalled_wall_clock_never_stretches_the_deadline(state_store, sign_quote):
    stalled = Clock(float(DESK_NOW))
    authorizer, cassette = _authorizer(
        state_store, sign_quote, READ, DECLINE, gate_s=3.7, wall=stalled
    )
    outcome = authorizer.handle(DECISION_ID)
    assert (outcome.status, outcome.reason) == ("declined", "card: desk busy")
    assert authorizer._desk.status("q:000001")["status"] == "approved"
    assert b'"approve"' not in b"".join(r.content for r in cassette.requests)


@pytest.mark.anyio
async def test_a_redelivered_webhook_is_a_duplicate(state_store, sign_quote):
    authorizer, cassette = _authorizer(state_store, sign_quote, READ, APPROVE)
    app = card_webhook_app(cassette.client(), authorizer, WEBHOOK_SECRET)
    body = webhook_event()
    async with _asgi(app) as http:
        await http.post(WEBHOOK_PATH, content=body, headers=sign_webhook(body))
        again = await http.post(
            WEBHOOK_PATH, content=body, headers=sign_webhook(body, msg_id="msg_2")
        )
    assert (again.status_code, again.json()) == (200, {"status": "duplicate"})
    assert len(cassette.requests) == 2


@pytest.mark.anyio
async def test_a_refused_webhook_logs_its_reason_alone(state_store, sign_quote, caplog):
    authorizer, cassette = _authorizer(state_store, sign_quote)
    app = card_webhook_app(cassette.client(), authorizer, WEBHOOK_SECRET)
    body = webhook_event()
    headers = sign_webhook(body, secret="another_secret")  # noqa: S106
    with caplog.at_level(logging.DEBUG, logger="swarm.card"):
        async with _asgi(app) as http:
            await http.post(WEBHOOK_PATH, content=body, headers=headers)
    assert [r.getMessage() for r in caplog.records if r.name == "swarm.card"] == [
        "card webhook refused (webhook: bad signature)"
    ]
    assert WEBHOOK_SECRET not in caplog.text
    assert DECISION_ID not in caplog.text
    assert headers["webhook-signature"] not in caplog.text
    assert app.debug is False


def test_the_card_webhook_server_binds_loopback(state_store, sign_quote):
    authorizer, cassette = _authorizer(state_store, sign_quote)
    app = card_webhook_app(cassette.client(), authorizer, WEBHOOK_SECRET)
    server = card_webhook_server(app, 8471)
    assert (server.config.host, server.config.port) == ("127.0.0.1", 8471)


def test_a_quote_closed_before_the_spend_seals_one_denial(state_store, sign_quote):
    authorizer, cassette = _authorizer(
        state_store, sign_quote, READ, DECLINE, approve=False
    )
    desk = authorizer._desk
    # As if the quote matched, then closed before the card could spend it.
    desk.card_quote = lambda *args, **kwargs: "q:000001"
    size = desk.registry.size()
    assert authorizer.handle(DECISION_ID) == CardOutcome(
        DECISION_ID, "declined", "card: no approved quote", "q:000001", False
    )
    assert desk.registry.size() == size + 1
    assert desk.registry.entry(size + 1).kind == "denial"
    assert len(cassette.requests) == 2


def test_a_busy_desk_answers_in_time_and_keeps_the_quote(state_store, sign_quote):
    soon = (200, decision_body(timeout_at="2027-01-15T08:16:41Z"))
    authorizer, cassette = _authorizer(state_store, sign_quote, soon, DECLINE)
    desk = authorizer._desk
    held, done = threading.Event(), threading.Event()

    def agent_payment():
        with desk._lock:
            held.set()
            done.wait(5)

    payer = threading.Thread(target=agent_payment)
    payer.start()
    held.wait(5)
    # The answer's record waits for the lock; the payment ends after the wait.
    threading.Timer(1.0, done.set).start()
    outcome = authorizer.handle(DECISION_ID)
    payer.join(5)
    assert (outcome.status, outcome.reason) == ("declined", "card: desk busy")
    assert outcome.sealed is False
    assert [m for m, _ in _sent(cassette)] == ["GET", "POST"]
    assert b'"approve"' not in b"".join(r.content for r in cassette.requests)
    assert desk.status("q:000001")["status"] == "approved"


def test_no_time_left_after_the_match_never_touches_the_quote(state_store, sign_quote):
    authorizer, cassette = _authorizer(state_store, sign_quote, READ, DECLINE)
    desk = authorizer._desk
    clock = authorizer._monotonic
    found = desk.card_quote

    def slow_match(*args, **kwargs):
        clock.now += 3.6  # the match waited out the deadline
        return found(*args, **kwargs)

    desk.card_quote = slow_match
    size = desk.registry.size()
    assert authorizer.handle(DECISION_ID) == CardOutcome(
        DECISION_ID, "declined", "card: deadline passed", "q:000001", False
    )
    assert desk.status("q:000001")["status"] == "approved"
    assert desk.registry.size() == size + 1
    assert b'"approve"' not in b"".join(r.content for r in cassette.requests)


def test_a_late_receipt_counts_against_the_deadline(state_store, sign_quote):
    authorizer, cassette = _authorizer(state_store, sign_quote, READ, DECLINE)
    early = float(DESK_NOW) - 3.7
    outcome = authorizer.handle(DECISION_ID, received=(early, early))
    assert (outcome.status, outcome.reason) == ("declined", "card: deadline passed")
    assert authorizer._desk.status("q:000001")["status"] == "approved"
    assert b'"approve"' not in b"".join(r.content for r in cassette.requests)


def test_a_read_naming_another_decision_is_never_approved(state_store, sign_quote):
    other = (200, dict(decision_body(), id=OTHER))
    authorizer, cassette = _authorizer(state_store, sign_quote, other, DECLINE)
    outcome = authorizer.handle(DECISION_ID)
    assert (outcome.status, outcome.reason) == (
        "declined",
        "card: malformed decision",
    )
    assert _sent(cassette) == [
        ("GET", DECISION_ID),
        ("POST", DECISION_ID + "/action"),
    ]
    assert b'"decline"' in cassette.requests[1].content


def test_a_decision_is_decided_once_across_a_restart(tmp_path, sign_quote):
    path = tmp_path / "card.db"
    first = StateStore(path)
    authorizer, _ = _authorizer(first, sign_quote, READ, APPROVE)
    assert authorizer.handle(DECISION_ID).status == "approved"
    first.close()
    second = StateStore(path)
    try:
        cassette = Cassette()
        # Only the store survives the restart; the decision never reaches a desk.
        again = CardAuthorizer(
            cassette.client(),
            authorizer._desk,
            AGENT_CARD_ID,
            CARD_ACCOUNT_ID,
            second,
            lambda: float(DESK_NOW),
        )
        assert again.handle(DECISION_ID) is None
        assert cassette.requests == []
    finally:
        second.close()


def test_a_lost_record_still_answers_and_names_the_decision(
    state_store, sign_quote, caplog
):
    authorizer, _ = _authorizer(state_store, sign_quote, READ, APPROVE)

    def broken(*args):
        raise OSError("disk full")

    authorizer._desk.record_card = broken
    with caplog.at_level(logging.ERROR, logger="swarm.card"):
        assert authorizer.handle(DECISION_ID).status == "approved"
    assert [r.getMessage() for r in caplog.records if r.name == "swarm.card"] == [
        f"card record failed for {DECISION_ID} (approved, OSError)"
    ]


@pytest.mark.anyio
async def test_a_failing_authorizer_answers_500_and_logs_the_type(
    state_store, sign_quote, caplog
):
    authorizer, cassette = _authorizer(state_store, sign_quote)

    def broken(*args, **kwargs):
        raise RuntimeError(WEBHOOK_SECRET)

    authorizer.handle = broken
    app = card_webhook_app(cassette.client(), authorizer, WEBHOOK_SECRET)
    body = webhook_event()
    with caplog.at_level(logging.DEBUG, logger="swarm.card"):
        async with _asgi(app) as http:
            answer = await http.post(
                WEBHOOK_PATH, content=body, headers=sign_webhook(body)
            )
    assert (answer.status_code, answer.content) == (500, b"")
    assert [r.getMessage() for r in caplog.records if r.name == "swarm.card"] == [
        "card webhook failed (RuntimeError)"
    ]
    assert WEBHOOK_SECRET not in caplog.text
