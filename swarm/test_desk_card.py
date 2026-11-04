import json
import threading

import httpx
import pytest

from bank.card import CardDecisionRail, read_authorization
from bank.conftest import (
    AGENT_CARD_ID,
    CARD_ACCOUNT_ID,
    DECISION_ID,
    Cassette,
    RecordingRail,
    decision_body,
)
from conftest import DESK_NOW
from gate.policy import Intent
from swarm.conftest import DEMO_INTENT

QUOTE = "q:000001"
GATE = b"\x01" * 32
APPROVED = (200, decision_body("responded", "approve"))
NO_QUOTE = {
    "status": "denied",
    "quote_id": QUOTE,
    "reason": "card: no approved quote",
    "payment_id": None,
}
DENIED_BUSY = {
    "status": "denied",
    "quote_id": QUOTE,
    "reason": "card: desk busy",
    "payment_id": None,
}


def _card_rail(*answers, now=DESK_NOW):
    reader = Cassette((200, decision_body())).client()
    auth = read_authorization(reader.real_time_decisions.retrieve(DECISION_ID))
    cassette = Cassette(*answers)
    rail = CardDecisionRail(
        cassette.client(),
        auth,
        "checking-881",
        CARD_ACCOUNT_ID,
        DESK_NOW + 4.0,
        lambda: float(now),
        card_id=AGENT_CARD_ID,
    )
    return rail, cassette


def _approved(make_desk, sign_quote, state, clock=None, publish=None, **rail):
    desk, holder = make_desk(
        bank=RecordingRail(balance=50000, **rail),
        intents=(DEMO_INTENT,),
        state=state,
        clock=clock,
        publish=publish,
        gate_key=GATE,
    )
    quoted = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    desk.approve(quoted["quote_id"], sign_quote(holder, quoted))
    return desk, holder


@pytest.mark.parametrize(
    ("ask", "found"),
    [
        (("acme-991", 20000, "USD"), QUOTE),
        (("acme-991", 19999, "USD"), None),
        (("evil-666", 20000, "USD"), None),
        (("acme-991", 20000, "EUR"), None),
        ("expired", None),
        ("unapproved", None),
    ],
)
def test_card_quote_finds_only_an_approved_matching_quote(
    make_desk, sign_quote, state_store, ask, found
):
    now = [DESK_NOW]
    if ask == "unapproved":
        desk, _ = make_desk(
            bank=RecordingRail(balance=50000),
            intents=(DEMO_INTENT,),
            state=state_store,
        )
        desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    else:
        desk, _ = _approved(make_desk, sign_quote, state_store, lambda: now[0])
    if ask == "expired":
        now[0] = DESK_NOW + 601
    args = ("acme-991", 20000, "USD") if isinstance(ask, str) else ask
    assert desk.card_quote(*args) == found


def test_card_quote_needs_a_bound_intent(make_desk, sign_quote, state_store):
    desk, holder = make_desk(bank=RecordingRail(balance=50000), state=state_store)
    quoted = desk.quote("acme-991", 20000, "USD", "A-991")
    desk.approve(quoted["quote_id"], sign_quote(holder, quoted))
    assert desk.card_quote("acme-991", 20000, "USD") is None


def test_a_certified_card_spend_is_sealed_as_the_bank_decision(
    make_desk, sign_quote, state_store
):
    desk, _ = _approved(make_desk, sign_quote, state_store)
    rail, cassette = _card_rail(APPROVED)
    assert desk.authorize_card(QUOTE, rail, 3.0) == {
        "status": "confirmed",
        "quote_id": QUOTE,
        "reason": "ok: executed",
        "payment_id": DECISION_ID,
    }
    entry = desk.registry.entry(desk.registry.size())
    assert (entry.kind, json.loads(entry.body)["payment_id"]) == (
        "execution",
        DECISION_ID,
    )
    assert state_store.records("pending") == []
    assert len(cassette.requests) == 1


def test_a_quote_pays_once_by_card_or_by_confirm(make_desk, sign_quote, state_store):
    desk, _ = _approved(make_desk, sign_quote, state_store)
    rail, _ = _card_rail(APPROVED)
    first = desk.authorize_card(QUOTE, rail, 3.0)
    assert desk.confirm(QUOTE) == first
    assert desk.bank.calls == []
    assert desk.card_quote("acme-991", 20000, "USD") is None


def test_a_confirmed_quote_is_never_spent_by_card(make_desk, sign_quote, state_store):
    desk, _ = _approved(make_desk, sign_quote, state_store)
    first = desk.confirm(QUOTE)
    assert first["status"] == "confirmed"
    rail, cassette = _card_rail(APPROVED)
    assert desk.authorize_card(QUOTE, rail, 3.0) == NO_QUOTE
    assert cassette.requests == []
    assert desk.card_quote("acme-991", 20000, "USD") is None
    assert desk.confirm(QUOTE) == first


def test_two_authorizations_for_one_quote_approve_once(
    make_desk, sign_quote, state_store
):
    desk, _ = _approved(make_desk, sign_quote, state_store)
    first, _ = _card_rail(APPROVED)
    second, cassette = _card_rail(APPROVED)
    assert desk.authorize_card(QUOTE, first, 3.0)["status"] == "confirmed"
    assert desk.authorize_card(QUOTE, second, 3.0) == NO_QUOTE
    assert cassette.requests == []


@pytest.mark.parametrize("ask", ["expired", "unknown", "denied"])
def test_a_quote_that_is_not_approved_answers_no_card(
    make_desk, sign_quote, state_store, ask
):
    now = [DESK_NOW]
    desk, holder = _approved(make_desk, sign_quote, state_store, lambda: now[0])
    quote_id = QUOTE
    if ask == "expired":
        late = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
        quote_id = late["quote_id"]
        now[0] = DESK_NOW + 601
        desk.approve(quote_id, sign_quote(holder, late))
    elif ask == "unknown":
        quote_id = "q:000099"
    else:
        again = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
        quote_id = again["quote_id"]
        desk.approve(quote_id, sign_quote(holder, again))
        desk.confirm(QUOTE)
        assert desk.confirm(quote_id)["reason"] == "intent: already used"
    rail, cassette = _card_rail(APPROVED)
    assert desk.authorize_card(quote_id, rail, 3.0) == dict(NO_QUOTE, quote_id=quote_id)
    assert cassette.requests == []


@pytest.mark.parametrize(
    ("answers", "reason"),
    [
        ((), "card: deadline passed"),
        (
            (
                httpx.ReadTimeout("lost"),
                (200, decision_body("responded", "decline")),
            ),
            "card: declined at the bank",
        ),
        (
            (httpx.ReadTimeout("lost"), (200, decision_body("timed_out"))),
            "card: deadline passed",
        ),
    ],
    ids=["late", "declined", "timed out"],
)
def test_a_definite_card_failure_leaves_the_intent_free(
    make_desk, sign_quote, state_store, answers, reason
):
    desk, _ = _approved(make_desk, sign_quote, state_store)
    rail, _ = _card_rail(*answers, now=DESK_NOW + (0 if answers else 3.5))
    assert desk.authorize_card(QUOTE, rail, 3.0) == {
        "status": "denied",
        "quote_id": QUOTE,
        "reason": reason,
        "payment_id": None,
    }
    assert state_store.records("pending") == []
    assert desk.reconcile_intent("i:000001")["status"] == "signed"
    assert desk.registry.entry(desk.registry.size()).kind == "denial"


def test_a_differing_authorization_leaves_the_intent_free(
    make_desk, sign_quote, state_store
):
    desk, holder = make_desk(
        bank=RecordingRail(balance=50000),
        intents=(Intent(19999, "USD", "acme-991", "A-991"),),
        state=state_store,
        gate_key=GATE,
    )
    quoted = desk.quote("acme-991", 19999, "USD", "A-991", intent_id="i:000001")
    desk.approve(quoted["quote_id"], sign_quote(holder, quoted))
    rail, cassette = _card_rail(APPROVED)
    result = desk.authorize_card(QUOTE, rail, 3.0)
    assert result["reason"] == "card: authorization differs"
    assert cassette.requests == []
    assert state_store.records("pending") == []
    assert desk.reconcile_intent("i:000001")["status"] == "signed"


def test_an_unknown_card_outcome_keeps_the_intent_blocked(
    make_desk, sign_quote, state_store
):
    desk, holder = _approved(make_desk, sign_quote, state_store)
    lost = (httpx.ReadTimeout("lost"), httpx.ConnectError("down"))
    rail, _ = _card_rail(*lost)
    assert desk.authorize_card(QUOTE, rail, 3.0)["reason"] == "bank: outcome unknown"
    [(quote_id, journal)] = state_store.records("pending")
    assert (quote_id, json.loads(journal)["rail"]) == (QUOTE, "card")
    assert desk.reconcile().pending == (QUOTE,)
    again = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    desk.approve(again["quote_id"], sign_quote(holder, again))
    assert desk.confirm(again["quote_id"])["reason"] == "intent: unsettled"
    assert desk.bank.calls == []


def test_an_unknown_card_outcome_survives_a_restart_and_a_late_lookup(
    make_desk, sign_quote, state_store
):
    now = [DESK_NOW]
    desk, _ = _approved(make_desk, sign_quote, state_store, lambda: now[0])
    lost = (httpx.ReadTimeout("lost"), httpx.ConnectError("down"))
    desk.authorize_card(QUOTE, _card_rail(*lost)[0], 3.0)
    now[0] = DESK_NOW + 86_400
    after, _ = make_desk(
        bank=RecordingRail(balance=50000),
        state=state_store,
        clock=lambda: now[0],
        register=False,
        gate_key=GATE,
    )
    assert after.reconcile_intent("i:000001")["status"] == "unsettled"
    assert after.reconcile().pending == (QUOTE,)
    assert after.bank.lookups == []
    assert [k for k, _ in state_store.records("pending")] == [QUOTE]


def test_card_approvals_are_not_missing_transfers(make_desk, sign_quote, state_store):
    desk, _ = _approved(make_desk, sign_quote, state_store)
    desk.authorize_card(QUOTE, _card_rail(APPROVED)[0], 3.0)
    view = desk.reconcile().view()
    assert (view["missing"], view["transfers"], view["unbacked"]) == ([], 0, [])


def test_a_card_spend_on_an_ach_desk_is_no_ach_payment(
    make_desk, sign_quote, state_store
):
    desk, _ = _approved(make_desk, sign_quote, state_store, ach=True)
    done = desk.authorize_card(QUOTE, _card_rail(APPROVED)[0], 3.0)
    assert done["payment_id"] == DECISION_ID
    assert state_store.records("ach") == []
    assert desk.lifecycle(DECISION_ID) is None


def test_a_busy_desk_answers_no_card(make_desk, sign_quote, state_store):
    desk, _ = _approved(make_desk, sign_quote, state_store)
    rail, cassette = _card_rail(APPROVED)
    seen = {}

    def work(bank, verifier):
        racer = threading.Thread(
            target=lambda: seen.update(r=desk.authorize_card(QUOTE, rail, 0.05))
        )
        racer.start()
        racer.join()

    desk.guarded(work)
    assert seen["r"] == DENIED_BUSY
    assert cassette.requests == []
    assert desk.card_quote("acme-991", 20000, "USD") == QUOTE


def test_a_two_step_desk_answers_no_card(make_desk, sign_quote, state_store):
    desk, _ = _approved(make_desk, sign_quote, state_store, two_step=True)
    rail, cassette = _card_rail(APPROVED)
    assert desk.authorize_card(QUOTE, rail, 3.0) == dict(
        DENIED_BUSY, reason="card: two-step desk"
    )
    assert cassette.requests == []


def test_a_quote_whose_intent_is_held_at_the_bank_answers_no_card(
    make_desk, sign_quote, state_store
):
    desk, _ = _approved(make_desk, sign_quote, state_store)
    # A hold kept from an earlier two-step run, for the quote's own intent.
    desk._holds["q:000000"] = {
        "intent_id": "i:000001",
        "idempotency_key": "mandate-cert-old",
        "transfer_id": None,
        "expires_at": DESK_NOW + 600,
        "rail": "sandbox",
    }
    rail, cassette = _card_rail(APPROVED)
    assert desk.authorize_card(QUOTE, rail, 3.0) == dict(
        DENIED_BUSY, reason="card: held at the bank"
    )
    assert cassette.requests == []
    assert desk.card_quote("acme-991", 20000, "USD") == QUOTE


def test_a_card_needs_a_durable_desk(make_desk, sign_quote):
    desk, holder = make_desk(bank=RecordingRail(balance=50000), intents=(DEMO_INTENT,))
    quoted = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    desk.approve(quoted["quote_id"], sign_quote(holder, quoted))
    rail, cassette = _card_rail(APPROVED)
    with pytest.raises(ValueError, match="card authorizations need a durable desk"):
        desk.authorize_card(QUOTE, rail, 3.0)
    assert cassette.requests == []


def test_an_answer_without_a_sealed_confirm_is_registered(
    make_desk, sign_quote, state_store
):
    lines = []
    desk, _ = _approved(make_desk, sign_quote, state_store, publish=lines.append)
    size = desk.registry.size()
    summary = "Card 200.00 USD at ACME 991 (acme-991) from checking-881"
    desk.record_card(
        DECISION_ID, "declined", "card: no approved quote", None, False, summary
    )
    desk.record_card(DECISION_ID, "approved", "ok: executed", QUOTE, True, summary)
    assert desk.registry.size() == size + 1
    entry = desk.registry.entry(size + 1)
    assert (entry.kind, entry.body) == (
        "denial",
        '{"payment_id":"sandbox_real_time_decision_b4ni7vda7z380dn9lb5x",'
        '"quote_id":null,"reason":"card: no approved quote","status":"declined"}',
    )
    assert [line.subject for line in lines[-2:]] == [
        {
            "step": "card",
            "quote_id": None,
            "status": "declined",
            "summary": summary,
            "payment_id": DECISION_ID,
            "reason": "card: no approved quote",
        },
        {
            "step": "card",
            "quote_id": QUOTE,
            "status": "approved",
            "summary": summary,
            "payment_id": DECISION_ID,
            "reason": "ok: executed",
        },
    ]


@pytest.mark.parametrize(
    "lefts", [(0.2,), (1.0, 0.2)], ids=["after the lock", "before the gate"]
)
def test_too_little_time_for_the_gate_keeps_the_quote(
    make_desk, sign_quote, state_store, lefts
):
    desk, _ = _approved(make_desk, sign_quote, state_store)
    rail, cassette = _card_rail(APPROVED)
    size = desk.registry.size()
    left = iter(lefts)
    assert (
        desk.authorize_card(QUOTE, rail, 3.0, time_left=lambda: next(left), gate_s=0.25)
        == DENIED_BUSY
    )
    assert cassette.requests == []
    assert desk.registry.size() == size
    assert state_store.records("pending") == []
    assert desk.status(QUOTE)["status"] == "approved"
    assert desk.authorize_card(QUOTE, rail, 3.0)["status"] == "confirmed"
