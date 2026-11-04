import base64
import itertools
import json

import pytest

from gate.certs import public_key_of
from gate.consent import Consent, certifying_key, sign_consent
from gate.state import StateStore
from swarm.holders import MAX_HOLDERS, HolderRegistry, unpair_bytes, verify_unpair

HOLDER = public_key_of(b"\x02" * 32)
UNPAIR_SIGNATURE = (
    "funkeiu1a6bTgwfybxQ+sD+Tvsvj6VueGAKqTooc1JBkljz9IoPavw+Eu/IMakx/TR9A18oGGuhY/eYM"
    "gdzZBA=="
)
UNSIGNED = Consent(
    20000, "USD", "acme-991", "A-991", "checking-881", "c0" * 16, 1800001600, b""
)


def _ids():
    counter = itertools.count(1)
    return lambda: f"h:{next(counter):016x}"


def _key(n):
    return public_key_of(bytes([n]) * 32)


def test_each_holder_gets_its_own_id():
    holders = HolderRegistry(_ids())
    assert [holders.pair(_key(n)) for n in (3, 4)] == [
        "h:0000000000000001",
        "h:0000000000000002",
    ]
    assert holders.key_of("h:0000000000000002") == _key(4)
    assert holders.paired_keys == (_key(3), _key(4))


def test_a_known_key_never_pairs_twice():
    holders = HolderRegistry(_ids())
    first = holders.pair(_key(3))
    assert holders.pair(_key(3)) is None
    assert holders.unpair(first) is True
    assert holders.pair(_key(3)) is None
    assert holders.paired_keys == ()


def test_a_drawn_id_already_taken_is_drawn_again():
    drawn = iter(["h:a", "h:a", "h:b"])
    holders = HolderRegistry(lambda: next(drawn))
    assert [holders.pair(_key(n)) for n in (3, 4)] == ["h:a", "h:b"]


def test_pairing_stops_at_the_bound_and_unpairing_frees_a_slot():
    holders = HolderRegistry(_ids())
    ids = [holders.pair(_key(n)) for n in range(3, 3 + MAX_HOLDERS)]
    assert None not in ids
    assert holders.pair(_key(100)) is None
    assert holders.unpair(ids[0]) is True
    assert holders.pair(_key(100)) == f"h:{MAX_HOLDERS + 1:016x}"
    assert len(holders.paired_keys) == MAX_HOLDERS


def test_unpairing_keeps_the_key_for_earlier_receipts():
    holders = HolderRegistry(_ids())
    first, second = holders.pair(_key(3)), holders.pair(_key(4))
    assert holders.unpair(first) is True
    assert holders.unpair(first) is False
    assert holders.unpair("h:unknown") is False
    assert holders.key_of(first) is None
    assert holders.key_ever(first) == _key(3)
    assert holders.paired_keys == (_key(4),)
    assert holders.all_keys == (_key(3), _key(4))
    assert holders.holder_of(_key(4)) == second
    assert holders.holder_of(_key(3)) is None


def test_the_certifying_holder_is_found_among_the_paired():
    holders = HolderRegistry(_ids())
    for n in (3, 4, 2):
        holders.pair(public_key_of(bytes([n]) * 32))
    signed = sign_consent(b"\x02" * 32, UNSIGNED, b"\x81" * 32)
    found = certifying_key(signed, holders.paired_keys)
    assert found == HOLDER
    assert holders.holder_of(found) == "h:0000000000000003"
    assert certifying_key(signed, (_key(3), _key(4))) is None


def test_unpair_bytes_golden():
    assert unpair_bytes(HOLDER) == (
        b"holder-unpair/v1:gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q="
    )
    assert verify_unpair(HOLDER, base64.b64decode(UNPAIR_SIGNATURE)) is True


@pytest.mark.parametrize(
    ("key", "signature"),
    [
        (_key(3), base64.b64decode(UNPAIR_SIGNATURE)),
        (HOLDER, b"\x00" * 64),
        (HOLDER, base64.b64decode(UNPAIR_SIGNATURE)[:63]),
        (HOLDER[:31], base64.b64decode(UNPAIR_SIGNATURE)),
    ],
)
def test_an_unpair_request_needs_the_holder_key_signature(key, signature):
    assert verify_unpair(key, signature) is False


def test_holders_survive_a_restart(state_store):
    holders = HolderRegistry(_ids(), state=state_store)
    first, second = holders.pair(_key(3)), holders.pair(_key(4))
    holders.unpair(first)
    path = state_store.path
    state_store.close()
    again = HolderRegistry(_ids(), state=StateStore(path))
    assert again.paired_keys == (_key(4),)
    assert again.all_keys == (_key(3), _key(4))
    assert again.key_of(second) == _key(4)
    assert again.pair(_key(3)) is None
    assert again.pair(_key(5)) == "h:0000000000000003"


def test_a_single_holder_desk_state_is_carried_over(state_store):
    legacy = json.dumps([base64.b64encode(HOLDER).decode()])
    state_store.put("holders", legacy)
    holders = HolderRegistry(_ids(), state=state_store)
    assert holders.paired_keys == (HOLDER,)
    assert holders.holder_of(HOLDER) == "h:0000000000000001"
    assert state_store.get("holders") == "[]"
    assert [k for k, _ in state_store.records("holder")] == ["h:0000000000000001"]
