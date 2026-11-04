import dataclasses

import pytest

from bank.api import PaymentRequest, RailError, ReplayError
from bank.conftest import Cassette, recorded
from bank.increase import IncreaseRail
from bank.rail import NO_TRANSFER, HoldingRail
from bank.test_increase import (
    ACCOUNTS,
    HTML,
    KEY,
    LOST,
    REQUEST,
    _body,
    _listed,
    _transfer,
)

HELD = recorded("account_transfer")["body"]["id"]
APPROVE = f"/account_transfers/{HELD}/approve"
CANCEL = f"/account_transfers/{HELD}/cancel"
AT = "2026-11-04T09:00:00Z"
REFUSED = (409, {"type": "invalid_operation_error", "status": 409})


def _held(**change):
    pending = {
        "status": "pending_approval",
        "transaction_id": None,
        "destination_transaction_id": None,
        "pending_transaction_id": "sandbox_pending_transaction_p1",
    }
    return _transfer(**{**pending, **change})


def _approved(by=None, **change):
    return _transfer(approval={"approved_at": AT, "approved_by": by}, **change)


def _canceled():
    return _held(
        status="canceled",
        cancellation={"canceled_at": AT, "canceled_by": None},
    )


def _two_step(*answers):
    cassette = Cassette(*answers)
    return IncreaseRail(cassette.client(), ACCOUNTS, two_step=True), cassette


def _sent(cassette):
    return [
        (r.method, r.url.path, r.headers.get("idempotency-key"))
        for r in cassette.requests
    ]


def test_a_two_step_rail_is_a_holding_rail():
    rail, _ = _two_step()
    assert isinstance(rail, HoldingRail)
    assert (rail.two_step, IncreaseRail(Cassette().client(), ACCOUNTS).two_step) == (
        True,
        False,
    )


def test_hold_posts_one_transfer_that_waits_for_approval():
    rail, cassette = _two_step((200, _held()))
    assert rail.hold(REQUEST, KEY) == HELD
    [sent] = cassette.requests
    assert (sent.method, sent.url.path, sent.headers["idempotency-key"]) == (
        "POST",
        "/account_transfers",
        KEY,
    )
    assert _body(sent) == {
        "account_id": "account_payer",
        "amount": 20000,
        "description": f"Mandate A-991 {KEY}",
        "destination_account_id": "account_payee",
        "require_approval": True,
    }


def test_confirm_approves_the_hold_under_its_own_key():
    rail, cassette = _two_step((200, _held()), (200, _approved()))
    rail.hold(REQUEST, KEY)
    payment = rail.execute(REQUEST, "h1", KEY)
    assert _sent(cassette) == [
        ("POST", "/account_transfers", KEY),
        ("POST", APPROVE, f"mandate-approve-{HELD}"),
    ]
    assert cassette.requests[1].content == b""
    assert (payment.payment_id, payment.status, payment.idempotency_key) == (
        HELD,
        "complete",
        KEY,
    )
    assert (payment.amount_cents, payment.action_hash) == (20000, "h1")


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (_approved(by="owner@example.com"), "bank: approved outside the gate"),
        (_canceled(), "bank: canceled at the bank"),
        (_held(), "bank: not complete"),
        (_approved(amount=1), "bank: transfer differs"),
        (_approved(id="sandbox_account_transfer_other"), "bank: transfer differs"),
    ],
)
def test_an_approval_that_is_not_this_certificates_payment_is_never_paid(
    answer, reason
):
    rail, _ = _two_step((200, _held()), (200, answer))
    rail.hold(REQUEST, KEY)
    with pytest.raises(RailError) as raised:
        rail.execute(REQUEST, "h1", KEY)
    assert str(raised.value) == reason


@pytest.mark.parametrize(
    ("read", "reason"),
    [
        (_canceled(), "bank: canceled at the bank"),
        (_approved(by="owner@example.com"), "bank: approved outside the gate"),
    ],
)
def test_a_refused_approval_is_decided_by_one_read(read, reason):
    rail, cassette = _two_step((200, _held()), REFUSED, (200, read))
    rail.hold(REQUEST, KEY)
    with pytest.raises(RailError) as raised:
        rail.execute(REQUEST, "h1", KEY)
    assert str(raised.value) == reason
    assert [(m, p) for m, p, _ in _sent(cassette)] == [
        ("POST", "/account_transfers"),
        ("POST", APPROVE),
        ("GET", f"/account_transfers/{HELD}"),
    ]


def test_a_lost_approval_is_settled_by_one_read():
    rail, cassette = _two_step((200, _held()), LOST, (200, _approved()))
    rail.hold(REQUEST, KEY)
    assert rail.execute(REQUEST, "h1", KEY).payment_id == HELD
    assert [r.method for r in cassette.requests] == ["POST", "POST", "GET"]


@pytest.mark.parametrize("read", [LOST, HTML, (404, {"type": "object_not_found"})])
def test_an_approval_nobody_can_read_is_an_unknown_outcome(read):
    rail, _ = _two_step((200, _held()), LOST, read)
    rail.hold(REQUEST, KEY)
    with pytest.raises(RailError, match="^bank: outcome unknown$"):
        rail.execute(REQUEST, "h1", KEY)


def test_a_certificate_without_its_hold_takes_the_one_step_path():
    rail, cassette = _two_step("idempotency_conflict")
    with pytest.raises(ReplayError):
        rail.execute(REQUEST, "h1", KEY)
    assert _body(cassette.requests[0])["require_approval"] is False


def test_a_hold_is_approved_at_most_once():
    rail, cassette = _two_step(
        (200, _held()), (200, _approved()), "idempotency_conflict"
    )
    rail.hold(REQUEST, KEY)
    rail.execute(REQUEST, "h1", KEY)
    with pytest.raises(ReplayError):
        rail.execute(REQUEST, "h1", KEY)
    assert [p for _, p, _ in _sent(cassette)].count(APPROVE) == 1


@pytest.mark.parametrize(
    ("answers", "raised"),
    [
        (("insufficient_balance", "balance_lookup"), ValueError),
        (((401, {"type": "invalid_api_key_error", "status": 401}),), RailError),
        (((400, {"type": "invalid_parameters_error", "status": 400}),), RailError),
        (("idempotency_conflict",), ReplayError),
    ],
)
def test_hold_refusals_map_like_transfers(answers, raised):
    rail, _ = _two_step(*answers)
    big = PaymentRequest("checking-881", "acme-991", 10**9, "USD", "A-991")
    with pytest.raises(raised):
        rail.hold(big, KEY)


def test_a_hold_whose_answer_is_lost_is_found_by_its_key():
    rail, cassette = _two_step(LOST, _listed(_held()), (200, _approved()))
    assert rail.hold(REQUEST, KEY) == HELD
    assert dict(cassette.requests[1].url.params) == {"idempotency_key": KEY}
    assert rail.execute(REQUEST, "h1", KEY).payment_id == HELD


@pytest.mark.parametrize("found", [_listed(), LOST, HTML])
def test_a_hold_found_nowhere_is_an_unknown_outcome(found):
    rail, _ = _two_step(LOST, found)
    with pytest.raises(RailError, match="^bank: outcome unknown$"):
        rail.hold(REQUEST, KEY)


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (_transfer(), "bank: not held for approval"),
        (_held(amount=1), "bank: transfer differs"),
    ],
)
def test_a_hold_the_bank_did_not_hold_as_asked_is_refused(answer, reason):
    rail, _ = _two_step((200, answer))
    with pytest.raises(RailError) as raised:
        rail.hold(REQUEST, KEY)
    assert str(raised.value) == reason


@pytest.mark.parametrize(
    ("listed", "after", "status"),
    [
        (_listed(_held()), [(200, _canceled())], "canceled"),
        (_listed(), [], NO_TRANSFER),
        (_listed(_transfer()), [], "complete"),
        (_listed(_canceled()), [], "canceled"),
    ],
)
def test_release_cancels_a_pending_hold_and_nothing_else(listed, after, status):
    rail, cassette = _two_step(listed, *after)
    assert rail.release(KEY) == status
    assert dict(cassette.requests[0].url.params) == {"idempotency_key": KEY}
    posts = [(p, k) for m, p, k in _sent(cassette) if m == "POST"]
    assert posts == ([(CANCEL, f"mandate-cancel-{HELD}")] if after else [])


def test_a_cancel_the_bank_refuses_is_decided_by_one_read():
    rail, cassette = _two_step(_listed(_held()), REFUSED, (200, _approved()))
    assert rail.release(KEY) == "complete"
    assert [(m, p) for m, p, _ in _sent(cassette)] == [
        ("GET", "/account_transfers"),
        ("POST", CANCEL),
        ("GET", f"/account_transfers/{HELD}"),
    ]


@pytest.mark.parametrize("answer", [LOST, HTML, (200, {"data": "x"})])
def test_a_release_that_cannot_read_the_bank_is_unavailable(answer):
    rail, _ = _two_step(answer)
    with pytest.raises(RailError, match="^bank: unavailable$"):
        rail.release(KEY)


def test_the_recorded_hold_and_approval_read_as_one_payment():
    held = recorded("account_transfer_pending")["body"]
    accounts = {
        "checking-881": held["account_id"],
        "acme-991": held["destination_account_id"],
    }
    cassette = Cassette("account_transfer_pending", "account_transfer_approved")
    rail = IncreaseRail(cassette.client(), accounts, two_step=True)
    request = PaymentRequest("checking-881", "acme-991", held["amount"], "USD", "A")
    assert rail.hold(request, held["idempotency_key"]) == held["id"]
    paid = rail.execute(request, "h1", held["idempotency_key"])
    assert (paid.payment_id, paid.status) == (held["id"], "complete")


@pytest.mark.parametrize(
    "change",
    [
        {"from_acct": "acme-991", "to_acct": "checking-881"},
        {"to_acct": "checking-881"},
        {"amount_cents": 1},
        {"currency": "EUR"},
        {"ref": "A-992"},
    ],
)
def test_a_certificate_for_another_payment_never_approves_the_hold(change):
    rail, cassette = _two_step((200, _held()))
    rail.hold(REQUEST, KEY)
    other = dataclasses.replace(REQUEST, **change)
    with pytest.raises(RailError, match="^bank: transfer differs$"):
        rail.execute(other, "h1", KEY)
    assert len(cassette.requests) == 1


OTHER = "sandbox_account_transfer_other"


@pytest.mark.parametrize(
    "listed",
    [
        _listed(_held(idempotency_key="mandate-cert-OTHER", id=OTHER)),
        _listed(_held(idempotency_key="mandate-cert-OTHER")),
        _listed(_held(id=OTHER)),
        _listed({"id": HELD, "idempotency_key": KEY}),
        _listed(_held(status="unheard_of")),
    ],
)
def test_release_never_acts_on_a_transfer_it_cannot_tell_is_its_hold(listed):
    rail, cassette = _two_step((200, _held()), listed, (200, _approved()))
    rail.hold(REQUEST, KEY)
    with pytest.raises(RailError, match="^bank: unavailable$"):
        rail.release(KEY)
    assert [m for m, _, _ in _sent(cassette)] == ["POST", "GET"]
    rail.execute(REQUEST, "h1", KEY)
    assert _sent(cassette)[-1] == ("POST", APPROVE, f"mandate-approve-{HELD}")


@pytest.mark.parametrize(
    "answer",
    [
        (200, {}),
        (200, _canceled() | {"id": OTHER}),
        (200, _held(status="unheard_of")),
    ],
)
def test_a_cancel_answer_that_is_not_this_hold_is_decided_by_one_read(answer):
    rail, cassette = _two_step(_listed(_held()), answer, (200, _canceled()))
    assert rail.release(KEY) == "canceled"
    assert [(m, p) for m, p, _ in _sent(cassette)] == [
        ("GET", "/account_transfers"),
        ("POST", CANCEL),
        ("GET", f"/account_transfers/{HELD}"),
    ]


@pytest.mark.parametrize(
    "read", [(200, {}), (200, _canceled() | {"id": OTHER}), LOST, HTML]
)
def test_a_cancel_nobody_can_read_keeps_the_hold(read):
    rail, cassette = _two_step(
        (200, _held()), _listed(_held()), (200, {}), read, (200, _approved())
    )
    rail.hold(REQUEST, KEY)
    with pytest.raises(RailError, match="^bank: unavailable$"):
        rail.release(KEY)
    rail.execute(REQUEST, "h1", KEY)
    assert _sent(cassette)[-1] == ("POST", APPROVE, f"mandate-approve-{HELD}")


@pytest.mark.parametrize(
    ("read", "after", "status"),
    [
        ((200, _held()), [(200, _canceled())], "canceled"),
        ((200, _approved()), [], "complete"),
        ((200, _canceled()), [], "canceled"),
    ],
)
def test_release_of_a_known_hold_reads_it_by_id(read, after, status):
    rail, cassette = _two_step(read, *after)
    assert rail.release(KEY, HELD) == status
    sent = [(m, p) for m, p, _ in _sent(cassette)]
    assert sent[0] == ("GET", f"/account_transfers/{HELD}")
    assert sent[1:] == ([("POST", CANCEL)] if after else [])


@pytest.mark.parametrize(
    "read",
    [
        LOST,
        HTML,
        (404, {"type": "object_not_found_error", "status": 404}),
        (200, {}),
        (200, _held(idempotency_key="mandate-cert-OTHER")),
    ],
)
def test_a_known_hold_the_bank_cannot_show_is_kept(read):
    rail, cassette = _two_step((200, _held()), read, (200, _approved()))
    rail.hold(REQUEST, KEY)
    with pytest.raises(RailError, match="^bank: unavailable$"):
        rail.release(KEY, HELD)
    assert [m for m, _, _ in _sent(cassette)] == ["POST", "GET"]
    rail.execute(REQUEST, "h1", KEY)
    assert _sent(cassette)[-1] == ("POST", APPROVE, f"mandate-approve-{HELD}")
