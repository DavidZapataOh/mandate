import base64
import threading

import pytest

from gate.anchor_public import AnchorRound, PublicAnchors
from gate.certs import public_key_of
from gate.conftest import (
    BlockingCalendar,
    RecordedCalendars,
    RecordedHeaders,
    recorded_aggregators,
)
from swarm.receipt import present
from swarm.test_receipt import GATE, HOLDER, _pay

MAGIC = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294" + "0108"
DIGEST = "fe28838c6cdcfc365aef8d643ea05cd90abb7e58ffe7f60dfb57ea077fcf071a"


def _anchors(store, calendars, calendar_for=None):
    return PublicAnchors(
        store,
        public_key_of(GATE),
        calendars,
        RecordedHeaders({}),
        clock=lambda: 1800002000,
        calendar_for=calendar_for or RecordedCalendars({}).for_uri,
        nonces=lambda: b"\x01" * 16,
    )


def test_a_receipt_carries_the_proof_its_seal_has(make_desk, sign_quote, state_store):
    anchors = _anchors(state_store, recorded_aggregators())
    desk, _ = make_desk(
        gate_key=GATE, holder_key=HOLDER, state=state_store, anchors=anchors
    )
    paid = _pay(desk, sign_quote, "acme-991", 20000, "A-991")["payment_id"]
    assert desk.proof_receipt(paid)["public_anchor"] is None
    assert anchors.round().stamped == 1
    receipt = desk.proof_receipt(paid)
    assert list(receipt)[-1] == "public_anchor"
    proof = base64.b64decode(receipt["public_anchor"]["ots"])
    assert proof.hex().startswith(MAGIC + DIGEST + "f010" + "01" * 16 + "08")
    assert receipt["public_anchor"]["bitcoin"] is None
    assert present(receipt, frozenset())["public_anchor"] == receipt["public_anchor"]


def test_confirm_never_waits_for_a_calendar(make_desk, sign_quote, state_store):
    calendars = recorded_aggregators(0)
    desk, _ = make_desk(
        gate_key=GATE,
        holder_key=HOLDER,
        state=state_store,
        anchors=_anchors(state_store, calendars),
    )
    done = _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    assert done["status"] == "confirmed"
    assert [c.submitted for c in calendars] == [[], [], [], []]


@pytest.mark.parametrize("held_at", ["stamp", "upgrade"])
def test_the_desk_works_while_a_calendar_is_slow(
    make_desk, sign_quote, state_store, held_at
):
    aggregators = recorded_aggregators()
    held = BlockingCalendar(
        aggregators[0] if held_at == "stamp" else RecordedCalendars({}).for_uri("")
    )
    if held_at == "stamp":
        anchors = _anchors(state_store, [held, *aggregators[1:]])
    else:
        anchors = _anchors(state_store, aggregators, lambda uri: held)
    desk, _ = make_desk(
        gate_key=GATE, holder_key=HOLDER, state=state_store, anchors=anchors
    )
    first = _pay(desk, sign_quote, "acme-991", 20000, "A-991")["payment_id"]
    if held_at == "upgrade":
        _anchors(state_store, recorded_aggregators()).round()
    rounds = []
    worker = threading.Thread(target=lambda: rounds.append(anchors.round()))
    worker.start()
    assert held.entered.wait(5)
    served = []

    def use_the_desk():
        served.append(_pay(desk, sign_quote, "acme-991", 100, "A-992")["status"])
        served.append(list(desk.proof_receipt(first))[-1])

    desk_call = threading.Thread(target=use_the_desk)
    desk_call.start()
    desk_call.join(5)
    # The desk answered while the calendar still held the round.
    assert worker.is_alive()
    assert served == ["confirmed", "public_anchor"]
    held.release.set()
    worker.join(5)
    stamped = 1 if held_at == "stamp" else 0
    assert rounds == [AnchorRound(stamped, 0, 1, None)]
    assert anchors.round().stamped == 1
