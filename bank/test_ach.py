import pytest

from bank import ach, increase
from bank.ach import simulate_cli
from bank.api import PaymentRequest, RailError, ReplayError
from bank.conftest import (
    ACH_RETURN,
    SENTINEL_KEY,
    Cassette,
    ach_body,
    ach_returned,
    ach_settled,
    named_accounts,
    recorded,
)
from bank.credentials import BANK_KEY_ENV
from bank.increase import (
    AchDestination,
    IncreaseRail,
    ensure_account_number,
    setup_cli,
)
from bank.rail import AchRail
from bank.reconcile import AchState, BankTransfer, compare
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

ACH_ID = "ach_transfer_uoxatyh3lt5evrsdvo7q"
DESTINATIONS = {"acme-991": AchDestination("987654321", "101050001")}
SETTLED_AT = "2027-01-15T09:16:40Z"
RETURNED_AT = "2027-01-16T08:16:40Z"
REFUSED = (409, {"type": "invalid_operation_error", "status": 409})


def _ach(*answers):
    cassette = Cassette(*answers)
    rail = IncreaseRail(cassette.client(), ACCOUNTS, destinations=DESTINATIONS)
    return rail, cassette


def _sent(cassette):
    return [(r.method, r.url.path, dict(r.url.params)) for r in cassette.requests]


def test_an_ach_rail_is_an_ach_rail():
    rail, _ = _ach()
    assert isinstance(rail, AchRail)
    assert (rail.ach, IncreaseRail(Cassette().client(), ACCOUNTS).ach) == (True, False)
    with pytest.raises(ValueError, match="ach and two-step are exclusive"):
        IncreaseRail(
            Cassette().client(), ACCOUNTS, two_step=True, destinations=DESTINATIONS
        )


def test_execute_posts_one_keyed_ach_transfer_to_the_payees_number():
    rail, cassette = _ach((200, ach_body()))
    payment = rail.execute(REQUEST, "h1", KEY)
    [sent] = cassette.requests
    assert (sent.method, sent.url.path, sent.headers["idempotency-key"]) == (
        "POST",
        "/ach_transfers",
        KEY,
    )
    assert _body(sent) == {
        "account_id": "account_payer",
        "amount": 20000,
        "statement_descriptor": f"Mandate A-991 {KEY}",
        "account_number": "987654321",
        "routing_number": "101050001",
        "funding": "checking",
        "individual_name": "acme-991",
        "require_approval": False,
    }
    assert (payment.payment_id, payment.status, payment.rail) == (
        ACH_ID,
        "pending_submission",
        "sandbox",
    )
    assert (payment.provider, payment.idempotency_key, payment.action_hash) == (
        "increase",
        KEY,
        "h1",
    )


def test_a_submitted_ach_transfer_is_the_payment():
    rail, _ = _ach((200, ach_settled()))
    assert rail.execute(REQUEST, "h1", KEY).status == "submitted"


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"amount": 1}, "bank: transfer differs"),
        ({"account_number": "111111111"}, "bank: transfer differs"),
        ({"routing_number": "021000021"}, "bank: transfer differs"),
        ({"idempotency_key": "mandate-cert-other"}, "bank: transfer differs"),
        ({"status": "rejected"}, "bank: refused"),
        ({"status": "canceled"}, "bank: refused"),
        ({"status": "pending_reviewing"}, "bank: not complete"),
        ({"status": "requires_attention"}, "bank: not complete"),
    ],
)
def test_an_ach_answer_that_is_not_this_payment_is_never_paid(change, reason):
    rail, _ = _ach((200, ach_body(**change)))
    with pytest.raises(RailError) as raised:
        rail.execute(REQUEST, "h1", KEY)
    assert str(raised.value) == reason


@pytest.mark.parametrize(
    ("answers", "raised"),
    [
        ((REFUSED, "balance_lookup"), ValueError),
        (((401, {"type": "invalid_api_key_error", "status": 401}),), RailError),
        (("idempotency_conflict",), ReplayError),
    ],
)
def test_ach_refusals_map_like_transfers(answers, raised):
    rail, _ = _ach(*answers)
    big = PaymentRequest("checking-881", "acme-991", 10**9, "USD", "A-991")
    with pytest.raises(raised):
        rail.execute(big, "h1", KEY)


def test_a_payee_without_an_ach_number_sends_nothing():
    rail, cassette = _ach()
    back = PaymentRequest("acme-991", "checking-881", 100, "USD", "A-991")
    with pytest.raises(ValueError, match="unknown account: checking-881"):
        rail.execute(back, "h1", KEY)
    assert cassette.requests == []


def test_a_lost_ach_answer_is_found_by_its_key():
    rail, cassette = _ach(LOST, _listed(), _listed(ach_body()))
    assert rail.execute(REQUEST, "h1", KEY).payment_id == ACH_ID
    assert _sent(cassette) == [
        ("POST", "/ach_transfers", {}),
        ("GET", "/account_transfers", {"idempotency_key": KEY}),
        ("GET", "/ach_transfers", {"idempotency_key": KEY}),
    ]


@pytest.mark.parametrize("found", [_listed(), LOST, HTML])
def test_an_ach_transfer_found_nowhere_is_an_unknown_outcome(found):
    rail, _ = _ach(LOST, _listed(), found)
    with pytest.raises(RailError, match="^bank: outcome unknown$"):
        rail.execute(REQUEST, "h1", KEY)


def test_a_rejected_ach_found_by_its_key_moved_nothing():
    rail, _ = _ach(_listed(), _listed(ach_body(status="rejected")))
    assert rail.reconcile(REQUEST, "h1", KEY) is None


def test_a_rejected_ach_under_another_key_never_says_nothing_moved():
    other = ach_body(status="rejected", idempotency_key="mandate-cert-other")
    rail, _ = _ach(_listed(), _listed(other))
    with pytest.raises(RailError, match="^bank: transfer differs$"):
        rail.reconcile(REQUEST, "h1", KEY)


def test_lookups_on_an_ach_rail_read_both_kinds():
    rail, cassette = _ach(
        _listed(),
        _listed(ach_body()),
        _listed(_transfer()),
        _listed(ach_returned()),
    )
    assert rail.transfer_by_key(KEY) == BankTransfer(
        ACH_ID, 20000, "pending_submission", KEY, "2027-01-15T08:16:40Z"
    )
    listed = rail.transfers("checking-881", "2027-01-01T00:00:00Z")
    assert [(t.transfer_id, t.status) for t in listed] == [
        (_transfer()["id"], "complete"),
        (ACH_ID, "returned"),
    ]
    assert [p for _, p, _ in _sent(cassette)] == [
        "/account_transfers",
        "/ach_transfers",
        "/account_transfers",
        "/ach_transfers",
    ]
    assert _sent(cassette)[3][2] == {
        "account_id": "account_payer",
        "created_at.on_or_after": "2027-01-01T00:00:00Z",
        "limit": "100",
    }


def test_an_account_transfer_under_the_key_wins_on_an_ach_rail():
    rail, cassette = _ach(_listed(_transfer()))
    assert rail.reconcile(REQUEST, "h1", KEY).payment_id == _transfer()["id"]
    assert len(cassette.requests) == 1


@pytest.mark.parametrize(
    ("body", "want"),
    [
        (ach_body(), AchState(ACH_ID, "pending_submission", None, None, None, None)),
        (ach_settled(), AchState(ACH_ID, "submitted", SETTLED_AT, None, None, None)),
        (
            ach_returned(),
            AchState(
                ACH_ID, "returned", SETTLED_AT, "R01", "insufficient_fund", RETURNED_AT
            ),
        ),
    ],
)
def test_ach_state_reads_the_lifecycle(body, want):
    rail, cassette = _ach((200, body))
    assert rail.ach_state(ACH_ID) == want
    assert _sent(cassette) == [("GET", f"/ach_transfers/{ACH_ID}", {})]


@pytest.mark.parametrize(
    "answer",
    [
        LOST,
        HTML,
        (404, {"type": "object_not_found_error", "status": 404}),
        (200, ach_body(status="returned")),
    ],
)
def test_an_unreadable_lifecycle_is_unavailable(answer):
    rail, _ = _ach(answer)
    with pytest.raises(RailError, match="^bank: unavailable$"):
        rail.ach_state(ACH_ID)


@pytest.mark.parametrize(
    "body",
    [
        ach_body(id="ach_transfer_other"),
        ach_settled(**{"return": ACH_RETURN}),
        ach_returned(settlement={"settled_at": "later"}),
        ach_returned(**{"return": dict(ACH_RETURN, raw_return_reason_code=None)}),
    ],
)
def test_a_lifecycle_that_is_not_this_transfers_is_unavailable(body):
    rail, _ = _ach((200, body))
    with pytest.raises(RailError, match="^bank: unavailable$"):
        rail.ach_state(ACH_ID)


def test_a_returned_payment_is_neither_counted_nor_unbacked():
    listed = [
        BankTransfer("ach_1", 100, "returned", "mandate-cert-j1", ""),
        BankTransfer("ach_2", 100, "returned", "mandate-cert-j2", ""),
        BankTransfer("ach_3", 100, "rejected", None, ""),
        BankTransfer("ach_4", 100, "submitted", "mandate-cert-j4", ""),
    ]
    sealed = {"ach_1": ("j1", True), "ach_4": ("j4", True), "ach_5": ("j5", True)}
    assert compare(listed, sealed, "sandbox") == (1, ("ach_2",), ("ach_5",))


def test_the_recorded_ach_answers_read_like_the_documented_ones():
    assert set(recorded("ach_transfer")["body"]) == set(ach_body())
    returned = recorded("ach_transfer_returned")["body"]
    rail, _ = _ach((200, returned))
    state = rail.ach_state(returned["id"])
    assert (state.status, state.return_code) == ("returned", "R01")


def test_connect_maps_payees_to_their_active_numbers():
    number = recorded("account_number")["body"]
    numbers = [dict(number, account_id="account_acme-991")]
    cassette = Cassette(
        named_accounts("checking-881", "acme-991"),
        (200, {"data": numbers, "next_cursor": None}),
    )
    rail = IncreaseRail.connect(cassette.client(), ach=True)
    assert rail.ach
    assert dict(cassette.requests[1].url.params) == {"status.in": "active"}
    assert rail.destination("acme-991") == AchDestination(
        number["account_number"], number["routing_number"]
    )
    with pytest.raises(ValueError, match="unknown account: checking-881"):
        rail.destination("checking-881")


def _one_step(*answers):
    cassette = Cassette(*answers)
    return IncreaseRail(cassette.client(), ACCOUNTS), cassette


@pytest.mark.parametrize(
    "body",
    [
        ach_body(),
        ach_settled(),
        ach_body(status="pending_reviewing"),
        ach_body(amount=1),
        ach_body(status=None),
        ach_returned(),
    ],
)
def test_an_ach_under_the_key_on_a_one_step_rail_is_never_not_paid(body):
    rail, cassette = _one_step(_listed(), _listed(body))
    with pytest.raises(RailError, match="^bank: not complete$"):
        rail.reconcile(REQUEST, "h1", KEY)
    assert [p for _, p, _ in _sent(cassette)] == [
        "/account_transfers",
        "/ach_transfers",
    ]


@pytest.mark.parametrize("status", ["rejected", "canceled"])
def test_an_ach_that_moved_nothing_reads_as_nothing_on_a_one_step_rail(status):
    rail, _ = _one_step(_listed(), _listed(ach_body(status=status)))
    assert rail.reconcile(REQUEST, "h1", KEY) is None


@pytest.mark.parametrize(
    "other",
    [
        ach_body(status="rejected", idempotency_key="mandate-cert-other"),
        {"id": "ach_transfer_x"},
    ],
)
def test_an_ach_under_another_key_differs_on_a_one_step_rail(other):
    rail, _ = _one_step(_listed(), _listed(other))
    with pytest.raises(RailError, match="^bank: transfer differs$"):
        rail.reconcile(REQUEST, "h1", KEY)


@pytest.mark.parametrize("found", [LOST, HTML, _listed("not a transfer")])
def test_an_unreadable_ach_lookup_on_a_one_step_rail_is_unknown(found):
    rail, _ = _one_step(_listed(), found)
    with pytest.raises(RailError, match="^bank: outcome unknown$"):
        rail.reconcile(REQUEST, "h1", KEY)


@pytest.mark.parametrize("ach", [False, True])
def test_two_transfers_listed_under_one_key_are_an_unknown_outcome(ach):
    answers = (_listed(), _listed(ach_body(status="rejected"), ach_body()))
    rail, _ = _ach(*answers) if ach else _one_step(*answers)
    with pytest.raises(RailError, match="^bank: outcome unknown$"):
        rail.reconcile(REQUEST, "h1", KEY)


def test_a_one_step_rail_lists_and_finds_ach_transfers_too():
    rail, cassette = _one_step(
        _listed(),
        _listed(ach_body()),
        _listed(_transfer()),
        _listed(ach_body()),
    )
    assert rail.transfer_by_key(KEY) == BankTransfer(
        ACH_ID, 20000, "pending_submission", KEY, "2027-01-15T08:16:40Z"
    )
    listed = rail.transfers("checking-881", "2027-01-01T00:00:00Z")
    assert [t.transfer_id for t in listed] == [_transfer()["id"], ACH_ID]
    assert [p for _, p, _ in _sent(cassette)] == [
        "/account_transfers",
        "/ach_transfers",
        "/account_transfers",
        "/ach_transfers",
    ]


@pytest.mark.parametrize("ach", [False, True])
@pytest.mark.parametrize("listing", [LOST, HTML, _listed({"id": "x"})])
def test_an_unreadable_ach_listing_leaves_the_transfers_unknown(ach, listing):
    answers = (_listed(_transfer()), listing)
    rail, _ = _ach(*answers) if ach else _one_step(*answers)
    with pytest.raises(RailError, match="^bank: unavailable$"):
        rail.transfers("checking-881", "2027-01-01T00:00:00Z")


def test_an_ach_rail_never_holds():
    rail, cassette = _ach()
    with pytest.raises(ValueError, match="ach and two-step are exclusive"):
        rail.hold(REQUEST, KEY)
    assert cassette.requests == []


@pytest.mark.parametrize("status", ["pending_approval", "canceled"])
def test_an_account_hold_under_the_key_stays_unsettled_on_an_ach_rail(status):
    rail, cassette = _ach(_listed(_transfer(status=status)))
    with pytest.raises(RailError, match="^bank: not complete$"):
        rail.reconcile(REQUEST, "h1", KEY)
    assert len(cassette.requests) == 1


def test_a_refusal_with_funds_enough_is_refused():
    rich = (200, dict(recorded("balance_lookup")["body"], available_balance=10**9))
    rail, _ = _ach(REFUSED, rich)
    with pytest.raises(RailError, match="^bank: refused$"):
        rail.execute(REQUEST, "h1", KEY)


@pytest.mark.parametrize(
    "lost",
    [
        (500, {"type": "internal_server_error", "status": 500}),
        (302, {"type": "redirect"}),
        (404, "not json"),
    ],
)
def test_an_ach_answer_that_is_no_refusal_is_looked_up(lost):
    rail, cassette = _ach(lost, _listed(), _listed(ach_body()))
    assert rail.execute(REQUEST, "h1", KEY).payment_id == ACH_ID
    assert len(cassette.requests) == 3


def test_connect_skips_numbers_it_cannot_pay():
    number = recorded("account_number")["body"]
    numbers = [
        dict(number, account_id="account_closed"),
        dict(number, account_id="account_acme-991", status="disabled"),
        dict(number, account_id="account_acme-991", account_number=None),
        dict(number, account_id="account_acme-991", routing_number=""),
        dict(number, account_id="account_acme-991", account_number="good"),
    ]
    cassette = Cassette(
        named_accounts("checking-881", "acme-991"),
        (200, {"data": numbers, "next_cursor": None}),
    )
    rail = IncreaseRail.connect(cassette.client(), ach=True)
    assert rail.destination("acme-991") == AchDestination(
        "good", number["routing_number"]
    )
    with pytest.raises(ValueError, match="unknown account: checking-881"):
        rail.destination("checking-881")


def test_listed_ach_times_are_written_in_utc():
    rail, _ = _ach(_listed(), _listed(ach_body(created_at="2027-01-15T10:16:40+02:00")))
    assert rail.transfer_by_key(KEY).created_at == "2027-01-15T08:16:40Z"


def _simulating(monkeypatch, *answers):
    cassette = Cassette(*answers)
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    monkeypatch.setattr(ach, "sandbox_client", lambda key: cassette.client())
    return cassette


def test_simulate_needs_the_key(monkeypatch, capsys):
    monkeypatch.delenv(BANK_KEY_ENV, raising=False)
    with pytest.raises(SystemExit) as stopped:
        simulate_cli(["return", ACH_ID])
    assert stopped.value.code == 2
    assert capsys.readouterr().err == (
        "bank rail unavailable: set INCREASE_SANDBOX_API_KEY\n"
    )


@pytest.mark.parametrize(
    "bad", ["account_transfer_x", "ach_transfer_ x", "../ach_transfer_x"]
)
def test_simulate_refuses_what_is_not_an_ach_transfer_id(monkeypatch, capsys, bad):
    cassette = _simulating(monkeypatch)
    with pytest.raises(SystemExit) as stopped:
        simulate_cli(["return", bad])
    assert stopped.value.code == 2
    assert capsys.readouterr().err == f"not an ACH transfer id: {bad}\n"
    assert cassette.requests == []


def test_simulate_return_is_labelled_and_keyed(monkeypatch, capsys):
    cassette = _simulating(monkeypatch, (200, ach_returned()))
    simulate_cli(["return", ACH_ID])
    assert capsys.readouterr().out == (
        f"SIMULATED RETURN of ACH transfer {ACH_ID}: R01 insufficient_fund\n"
    )
    [sent] = cassette.requests
    assert (sent.method, sent.url.path) == (
        "POST",
        f"/simulations/ach_transfers/{ACH_ID}/return",
    )
    assert sent.headers["idempotency-key"] == f"mandate-simulate-return-{ACH_ID}"
    assert _body(sent) == {"reason": "insufficient_fund"}


@pytest.mark.parametrize(
    ("step", "answer", "out"),
    [
        ("submit", ach_body(status="submitted"), "submitted"),
        ("settle", ach_settled(), "settled at 2027-01-15T09:16:40Z"),
    ],
)
def test_simulate_submit_and_settle_report_the_bank_status(
    monkeypatch, capsys, step, answer, out
):
    cassette = _simulating(monkeypatch, (200, answer))
    simulate_cli([step, ACH_ID])
    assert capsys.readouterr().out == f"ACH transfer {ACH_ID}: {out}\n"
    assert cassette.requests[0].url.path == (
        f"/simulations/ach_transfers/{ACH_ID}/{step}"
    )


def test_simulate_sends_the_reason_asked(monkeypatch, capsys):
    no_account = {
        **ach_returned()["return"],
        "raw_return_reason_code": "R03",
        "return_reason_code": "no_account",
    }
    returned = ach_returned(**{"return": no_account})
    cassette = _simulating(monkeypatch, (200, returned))
    simulate_cli(["return", ACH_ID, "--reason", "no_account"])
    assert _body(cassette.requests[0]) == {"reason": "no_account"}
    assert capsys.readouterr().out.endswith(": R03 no_account\n")


@pytest.mark.parametrize(
    ("answer", "err"),
    [
        (REFUSED, "bank refused the simulation: invalid_operation_error\n"),
        (LOST, "bank unavailable: no answer to the simulation\n"),
        (HTML, "bank unavailable: no answer to the simulation\n"),
    ],
)
def test_a_failed_simulation_says_why(monkeypatch, capsys, answer, err):
    _simulating(monkeypatch, answer)
    with pytest.raises(SystemExit) as stopped:
        simulate_cli(["settle", ACH_ID])
    assert stopped.value.code == 1
    assert capsys.readouterr().err == err


def test_setup_opens_one_ach_number_for_the_payee():
    cassette = Cassette((200, {"data": [], "next_cursor": None}), "account_number")
    number = recorded("account_number")["body"]
    assert ensure_account_number(
        cassette.client(), "account_acme-991", "acme-991"
    ) == AchDestination(number["account_number"], number["routing_number"])
    listed, created = cassette.requests
    assert dict(listed.url.params) == {
        "account_id": "account_acme-991",
        "status.in": "active",
    }
    assert created.headers["idempotency-key"] == "mandate-setup-ach-number-acme-991"
    assert _body(created) == {"account_id": "account_acme-991", "name": "acme-991 ach"}


def test_setup_with_ach_reports_the_payee_ready(monkeypatch, capsys):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    available = recorded("balance_lookup")["body"]["available_balance"]
    listed = named_accounts("checking-881", "acme-991")
    number = dict(recorded("account_number")["body"], account_id="account_acme-991")
    numbers = (200, {"data": [number], "next_cursor": None})
    cassette = Cassette(listed, "balance_lookup", numbers, listed, "balance_lookup")
    monkeypatch.setattr(increase, "sandbox_client", lambda key: cassette.client())
    setup_cli(["--fund-cents", str(available), "--ach"])
    assert capsys.readouterr().out == (
        "Sandbox accounts ready: checking-881, acme-991\n"
        f"checking-881 available: {available} cents\n"
        "ACH payee ready: acme-991\n"
    )
    assert [r.method for r in cassette.requests] == ["GET"] * 5


def test_setup_with_ach_names_a_payee_number_it_cannot_pay(monkeypatch, capsys):
    monkeypatch.setenv(BANK_KEY_ENV, SENTINEL_KEY)
    available = recorded("balance_lookup")["body"]["available_balance"]
    listed = named_accounts("checking-881", "acme-991")
    number = dict(
        recorded("account_number")["body"],
        account_id="account_acme-991",
        routing_number="",
    )
    numbers = (200, {"data": [number], "next_cursor": None})
    cassette = Cassette(listed, "balance_lookup", numbers)
    monkeypatch.setattr(increase, "sandbox_client", lambda key: cassette.client())
    with pytest.raises(SystemExit) as stopped:
        setup_cli(["--fund-cents", str(available), "--ach"])
    assert stopped.value.code == 2
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (
        "",
        "bank rail unavailable: no ACH number for acme-991\n",
    )
