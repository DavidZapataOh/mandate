import base64
import hashlib
import json

import pytest
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile

from gate.anchor_public import AnchorError, anchor_digest_of, stamp
from gate.conftest import OTS, OTS_FILE, recorded_aggregators, unb64

ROOT = "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87"
DIGEST = "fe28838c6cdcfc365aef8d643ea05cd90abb7e58ffe7f60dfb57ea077fcf071a"
FOREIGN = "c46a611449cff2230732c0128a2900a35731d006b3f035119c99840ebc89d54b"
MAGIC = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294" + "0108"
AGGREGATORS = [
    "https://a.pool.eternitywall.com",
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://ots.btc.catallaxy.com",
]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _block(header_hex: str) -> str:
    header = bytes.fromhex(header_hex)
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def test_recorded_fixtures_are_the_published_proofs():
    core, hello, golden = OTS["core29"], OTS["hello2015"], OTS["golden"]
    assert _sha(unb64(core["pending"])) == (
        "e91f4c5104cce1b425a94fbbb918d05d9f40d8424c6b06ffebb90369f1ede1d5"
    )
    assert _sha(unb64(core["upgraded"])) == (
        "ed42bc6232526a17fe069d40e786534c53b9671639bbaaa339d90161b7ca5a84"
    )
    assert _sha(unb64(hello["proof"])) == (
        "be61ecb940db2e4a6f89fbed59c8d4f7f74fa756cbc1fad1ad7aabcb2bf59c30"
    )
    assert _block(core["headers"]["892418"]) == (
        "0000000000000000000167a45f26c2afb6a0df3009f8241a647b950a79e3da58"
    )
    assert _block(core["headers"]["892421"]) == (
        "00000000000000000000b2862b8f686909ae1715c230ed562f0b3d76e9327a24"
    )
    assert _block(hello["header"]) == (
        "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319"
    )
    assert sorted(OTS["aggregators"]) == AGGREGATORS
    assert len(core["answers"]) == 4
    assert (golden["root"], golden["digest"]) == (ROOT, DIGEST)
    assert unb64(golden["pending"]).hex().startswith(MAGIC + DIGEST + "f010")
    assert (golden["confirmed"], golden["bitcoin"]) == (None, None)
    assert OTS["foreign"]["digest"] == FOREIGN
    assert unb64(OTS["foreign"]["pending"]).hex().startswith(MAGIC + FOREIGN + "f010")
    assert unb64(OTS["bare"]["pending"]).hex().startswith(MAGIC + ROOT + "f010")


GATE_PUBLIC = base64.b64decode("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=")
FOREIGN_PUBLIC = base64.b64decode("7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=")
FOREIGN_SIGNATURE = base64.b64decode(
    "qQwKZfmtGNJnLCQZQ7jU6WYJUGYg2xoXAkxAEQRn0t89WEY52T97Dg"
    "sxDnl4QUPnuA7PC0UQG5+pvybOiwqhAQ=="
)
D1 = bytes.fromhex(DIGEST)
D2 = bytes.fromhex("72e29c662d4e5e554b1ff7e3afea6a4e6d81de539cbe531322a9d4df596ba707")
L1 = "95a0ff324286745702887c14bd71711d727bbf9b64d0a6affc32bb704e63d6c3"
L2 = "babeea645a07b82440fb18c0c9e58b3325363d71ca99418ba8068d593a1f4b3a"
TIP = "3e1989951846d2540eb847d9ca51891d04b83d458c9721533eb4930ff43d778a"
CALENDARS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://btc.calendar.catallaxy.com",
    "https://finney.calendar.eternitywall.com",
]


def _calendars_of(proof):
    read = DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))
    return sorted(att.uri for _, att in read.timestamp.all_attestations())


def _golden_seal():
    return json.loads((OTS_FILE.parent / "receipt.json").read_text())["registry"][
        "seal"
    ]


def test_anchor_digest_binds_the_gate_key_and_the_signed_seal():
    seal = _golden_seal()
    assert anchor_digest_of(seal, GATE_PUBLIC) == D1
    sandbox = json.loads((OTS_FILE.parent / "receipt-sandbox.json").read_text())
    assert anchor_digest_of(sandbox["registry"]["seal"], GATE_PUBLIC) == D2
    # Another desk, same entries, same root and seal fields: another digest.
    foreign = {**seal, "signature": base64.b64encode(FOREIGN_SIGNATURE).decode()}
    assert anchor_digest_of(foreign, FOREIGN_PUBLIC).hex() == FOREIGN
    assert D1 != bytes.fromhex(ROOT)
    # The seal's time is part of it: a later seal over the same root differs.
    later = {**seal, "ts": seal["ts"] + 1}
    assert anchor_digest_of(later, GATE_PUBLIC) != D1


def test_one_tree_tip_per_batch_and_one_proof_per_root():
    calendars = recorded_aggregators()
    nonces = iter([b"\x01" * 16, b"\x02" * 16])
    first, second = stamp([D1, D2], calendars, lambda: next(nonces))
    assert [c.submitted for c in calendars] == [[bytes.fromhex(TIP)]] * 4
    assert first.hex().startswith(
        MAGIC + D1.hex() + "f010" + "01" * 16 + "08" + "f020" + L2 + "08"
    )
    assert second.hex().startswith(
        MAGIC + D2.hex() + "f010" + "02" * 16 + "08" + "f120" + L1 + "08"
    )
    assert _calendars_of(first) == _calendars_of(second) == CALENDARS


def test_a_lone_root_submits_its_nonced_digest():
    calendars = recorded_aggregators()
    stamp([D1], calendars, lambda: b"\x01" * 16)
    assert calendars[0].submitted == [bytes.fromhex(L1)]


@pytest.mark.parametrize("up", [0, 1])
def test_a_stamp_needs_two_calendars(up):
    with pytest.raises(AnchorError, match=f"^anchor: {up} of 4 calendars answered$"):
        stamp([D1], recorded_aggregators(up), lambda: b"\x01" * 16)


def test_two_calendars_are_enough():
    (proof,) = stamp([D1], recorded_aggregators(2), lambda: b"\x01" * 16)
    assert _calendars_of(proof) == CALENDARS[:2]
