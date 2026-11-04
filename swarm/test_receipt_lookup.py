import json

import pytest

from gate.state import StateStore
from swarm.receipt import receipt_hashes
from swarm.test_desk_state import _desk, _restart
from swarm.test_receipt import AUDITOR, GATE, GOLDEN, HOLDER, _pay

RECEIPT_HASH = "73fb45625595a413f1f2ee4ec0a19acb4bdf4709a1927856a9ee2f31a4c0391f"
ACTION_HASH = "52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b"
SECOND_RECEIPT_HASH = "e2b4913ad14c17006b0386c8cdc37524bbfea24bb76c2f86bf9c76b7285d8583"
SECOND_ACTION_HASH = "2f5c61e9234f140d465e5ea2081bd5bfc586c477efda5d10325d51372fcef057"
FIRST_LEAF = "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87"
SECOND_LEAF = "d0ad291d073b7655e945189b684ff45e486ae485817ac3cc97bcaca6c8873e9a"


def _two_paid(make_desk, sign_quote):
    desk, _ = make_desk(gate_key=GATE, holder_key=HOLDER)
    _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    _pay(desk, sign_quote, "acme-991", 20000, "A-992")
    return desk


def test_every_copy_of_a_receipt_has_its_receipt_and_action_hash():
    holder = json.loads(GOLDEN.read_text())
    auditor = json.loads(AUDITOR.read_text())
    assert receipt_hashes(holder) == (RECEIPT_HASH, ACTION_HASH)
    assert receipt_hashes(auditor) == (RECEIPT_HASH, ACTION_HASH)
    # The public anchor is stamped after signing and changes as a round lands.
    anchored = {**holder, "public_anchor": {"status": "confirmed", "height": 1}}
    assert receipt_hashes(anchored) == (RECEIPT_HASH, ACTION_HASH)


@pytest.mark.parametrize(
    "change",
    [
        {"sd": 7},
        {"sd": "é~"},
        {"certificate": "not-a-jws"},
        {"certificate": "a.e30.b"},
    ],
)
def test_a_receipt_that_does_not_read_has_no_hashes(change):
    with pytest.raises(ValueError, match="^receipt: unreadable$"):
        receipt_hashes({**json.loads(GOLDEN.read_text()), **change})


def test_the_desk_finds_each_receipt_by_its_receipt_hash_and_action_hash(
    make_desk, sign_quote
):
    desk = _two_paid(make_desk, sign_quote)
    first, second = desk.proof_receipt("pay:000001"), desk.proof_receipt("pay:000002")
    assert desk.receipt_by_hash(RECEIPT_HASH) == first
    assert desk.receipt_by_hash(ACTION_HASH) == first
    assert desk.receipt_by_hash(SECOND_RECEIPT_HASH) == second
    assert desk.receipt_by_hash(SECOND_ACTION_HASH) == second


def test_no_leaf_hash_finds_a_receipt(make_desk, sign_quote):
    desk = _two_paid(make_desk, sign_quote)
    second = desk.proof_receipt("pay:000002")
    # The second receipt's inclusion proof carries the first payment's leaf.
    assert second["registry"]["proof"]["siblings"] == [FIRST_LEAF]
    assert desk.receipt_by_hash(FIRST_LEAF) is None
    assert desk.receipt_by_hash(SECOND_LEAF) is None
    assert desk.receipt_by_hash("ab" * 32) is None


def test_a_lookup_hands_out_a_copy(make_desk, sign_quote):
    desk = _two_paid(make_desk, sign_quote)
    desk.receipt_by_hash(RECEIPT_HASH)["payment_id"] = "pay:999999"
    assert desk.receipt_by_hash(RECEIPT_HASH)["payment_id"] == "pay:000001"


def test_a_restarted_desk_finds_a_receipt_by_its_hashes(state_store, sign_quote):
    desk = _desk(state_store)
    _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    again, _ = _restart(state_store)
    assert again.receipt_by_hash(RECEIPT_HASH) == json.loads(GOLDEN.read_text())
    assert again.receipt_by_hash(ACTION_HASH) == json.loads(GOLDEN.read_text())


def test_a_stored_receipt_that_does_not_read_is_found_by_no_hash(
    state_store, sign_quote
):
    _pay(_desk(state_store), sign_quote, "acme-991", 20000, "A-991")
    broken = {**json.loads(GOLDEN.read_text()), "certificate": "not-a-jws"}
    state_store.put_record("receipt", "pay:000001", json.dumps(broken))
    path = state_store.path
    state_store.close()
    store = StateStore(path)
    try:
        again = _desk(store, 101)
        assert again.receipt_by_hash(RECEIPT_HASH) is None
        assert again.proof_receipt("pay:000001") == broken
    finally:
        store.close()
