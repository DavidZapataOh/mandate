import base64
import hashlib
import json
import threading

import httpx2
import pytest
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpKECCAK256, OpSHA1, OpSHA256
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
)
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from gate.anchor_public import (
    BLOCK_SOURCE,
    STAMP_BATCH,
    UPGRADE_BATCH,
    AnchorError,
    AnchorRound,
    Calendar,
    EsploraHeaders,
    PublicAnchors,
    anchor_digest_of,
    attested_heights,
    block_hash,
    confirm,
    explorer_can_read,
    stamp,
    upgrade,
)
from gate.conftest import (
    OTS,
    OTS_FILE,
    BlockingCalendar,
    RecordedCalendars,
    RecordedHeaders,
    recorded_aggregators,
    unb64,
)
from gate.state import StateStore

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


CORE = bytes.fromhex("94ec151f452a221393d08f6b02fb30baacbeb59f194611f49069e7f5509b46fe")
PENDING = unb64(OTS["core29"]["pending"])
UPGRADED = unb64(OTS["core29"]["upgraded"])
HELLO = unb64(OTS["hello2015"]["proof"])
HELLO_DIGEST = bytes.fromhex(OTS["hello2015"]["digest"])
H18 = bytes.fromhex(OTS["core29"]["headers"]["892418"])
H21 = bytes.fromhex(OTS["core29"]["headers"]["892421"])
H15 = bytes.fromhex(OTS["hello2015"]["header"])
FLIPPED = H18[:-1] + bytes([H18[-1] ^ 1])
HASH18 = "0000000000000000000167a45f26c2afb6a0df3009f8241a647b950a79e3da58"


def test_upgrade_matches_the_reference_client():
    calendars = RecordedCalendars(OTS["core29"]["answers"])
    assert upgrade(PENDING, calendars.for_uri) == UPGRADED
    assert sorted(calendars.asked) == CALENDARS


def test_attested_heights_are_the_blocks_ots_info_names():
    assert attested_heights(UPGRADED) == [892418, 892421, 892459, 892534]
    assert attested_heights(PENDING) == []


def test_one_round_asks_each_calendar_once_per_commitment():
    nonces = iter([b"\x01" * 16, b"\x02" * 16])
    first, second = stamp([D1, D2], recorded_aggregators(), lambda: next(nonces))
    calendars, cache = RecordedCalendars({}), {}
    assert upgrade(first, calendars.for_uri, cache) == first
    assert upgrade(second, calendars.for_uri, cache) == second
    assert sorted(calendars.asked) == CALENDARS


class _BrokenCalendar:
    """A calendar whose answer is neither a timestamp nor a not-found."""

    def submit(self, digest: bytes, timeout: float | None = None) -> Timestamp:
        raise RuntimeError("calendar answered 502")

    def get_timestamp(
        self, commitment: bytes, timeout: float | None = None
    ) -> Timestamp:
        raise RuntimeError("calendar answered 502")


def test_one_broken_calendar_does_not_stop_the_others():
    calendars = RecordedCalendars(OTS["core29"]["answers"])
    broken = sorted(CALENDARS)[0]

    def calendar_for(uri: str) -> Calendar:
        return _BrokenCalendar() if uri == broken else calendars.for_uri(uri)

    upgraded = upgrade(PENDING, calendar_for)
    assert upgraded != PENDING
    assert attested_heights(upgraded) != []
    assert upgrade(PENDING, lambda uri: _BrokenCalendar()) == PENDING


def test_upgrade_never_asks_a_calendar_off_the_whitelist():
    lone = DetachedTimestampFile(OpSHA256(), Timestamp(D1))
    lone.timestamp.attestations.add(PendingAttestation("https://calendar.example.com"))
    ctx = BytesSerializationContext()
    lone.serialize(ctx)
    calendars = RecordedCalendars({})
    assert upgrade(ctx.getbytes(), calendars.for_uri) == ctx.getbytes()
    assert calendars.asked == []


def test_confirm_returns_the_block_time():
    assert confirm(UPGRADED, CORE, 892418, H18) == 1744655054
    assert block_hash(H18) == HASH18


@pytest.mark.parametrize(
    ("proof", "digest", "height", "header", "reason"),
    [
        (UPGRADED, D1, 892418, H18, "proof is not over this seal's anchor digest"),
        (b"not a proof", CORE, 892418, H18, "proof malformed"),
        (
            HELLO, HELLO_DIGEST, 358391, H15,
            "proof uses an operation the explorer cannot check",
        ),
        (UPGRADED, CORE, 892419, H18, "proof names no Bitcoin block 892419"),
        (UPGRADED, CORE, 892418, H18[:79], "a block header is 80 bytes"),
        (UPGRADED, CORE, 892418, FLIPPED, "header misses its proof-of-work target"),
        (UPGRADED, CORE, 892418, H15, "header is below the work floor"),
        (
            UPGRADED, CORE, 892418, H21,
            "block header does not hold the proof's merkle root",
        ),
    ],
)  # fmt: skip
def test_confirm_refuses(proof, digest, height, header, reason):
    with pytest.raises(AnchorError, match=f"^anchor: {reason}$"):
        confirm(proof, digest, height, header)


def _source(routes):
    seen = []

    def answer(request):
        seen.append((request.method, str(request.url)))
        status, text = routes.get(str(request.url), (404, "Block not found"))
        return httpx2.Response(status, text=text)

    client = httpx2.Client(transport=httpx2.MockTransport(answer))
    return EsploraHeaders(client), seen


def test_headers_come_from_the_block_source_by_height():
    height_url = f"{BLOCK_SOURCE}/block-height/892418"
    header_url = f"{BLOCK_SOURCE}/block/{HASH18}/header"
    source, seen = _source({height_url: (200, HASH18), header_url: (200, H18.hex())})
    assert source.header(892418) == H18
    assert seen == [("GET", height_url), ("GET", header_url)]


@pytest.mark.parametrize(
    ("hash_answer", "header_answer", "reason"),
    [
        ((503, "busy"), None, "header source unavailable"),
        ((200, "zz" * 32), None, "header source unavailable"),
        ((200, HASH18), (200, H21.hex()), "header source answered another block"),
    ],
)
def test_a_block_source_failure_is_unavailable(hash_answer, header_answer, reason):
    routes = {f"{BLOCK_SOURCE}/block-height/892418": hash_answer}
    if header_answer is not None:
        routes[f"{BLOCK_SOURCE}/block/{HASH18}/header"] = header_answer
    source, _ = _source(routes)
    with pytest.raises(AnchorError, match=f"^anchor: {reason}$"):
        source.header(892418)


def _seal(seq, root):
    return {
        "v": 1, "anchor_id": f"anch:{seq:06d}", "seq_from": seq, "seq_to": seq,
        "root": root, "ts": 1800001000,
        "signature": base64.b64encode(bytes(64)).decode(),
    }  # fmt: skip


def _anchors(store, calendars=None, answers=None, headers=None, calendar_for=None):
    return PublicAnchors(
        store,
        GATE_PUBLIC,
        recorded_aggregators() if calendars is None else calendars,
        RecordedHeaders({}) if headers is None else headers,
        clock=lambda: 1800002000,
        calendar_for=calendar_for or RecordedCalendars(answers or {}).for_uri,
        nonces=lambda: b"\x01" * 16,
    )


def test_a_round_stamps_each_new_seal_once(state_store):
    state_store.add_seal(_golden_seal())
    state_store.add_seal(_seal(2, D2.hex()))
    calendars = recorded_aggregators()
    anchors = _anchors(state_store, calendars)
    assert anchors.round() == AnchorRound(2, 0, 2, None)
    assert anchors.round() == AnchorRound(0, 0, 2, None)
    assert [len(c.submitted) for c in calendars] == [1, 1, 1, 1]
    view = anchors.view(1)
    assert (view["v"], view["bitcoin"]) == (1, None)
    proof = base64.b64decode(view["ots"]).hex()
    assert proof.startswith(MAGIC + DIGEST + "f010")
    assert not proof.startswith(MAGIC + ROOT)
    assert anchors.view(3) is None


def test_proofs_outlive_the_process(tmp_path):
    path = tmp_path / "state" / "state.db"
    store = StateStore(path)
    store.add_seal(_golden_seal())
    first = _anchors(store)
    first.round()
    kept = first.view(1)
    store.close()
    again = StateStore(path)
    calendars = recorded_aggregators()
    later = _anchors(again, calendars)
    assert later.view(1) == kept
    assert later.round().stamped == 0
    assert calendars[0].submitted == []
    again.close()


def test_a_round_without_two_calendars_stores_nothing(state_store):
    state_store.add_seal(_golden_seal())
    down = _anchors(state_store, recorded_aggregators(1))
    assert down.round() == AnchorRound(0, 0, 0, "anchor: 1 of 4 calendars answered")
    assert down.view(1) is None
    assert _anchors(state_store).round().stamped == 1


def test_a_round_stamps_at_most_a_batch(state_store):
    for seq in range(1, STAMP_BATCH + 2):
        state_store.add_seal(_seal(seq, f"{seq:064x}"))
    anchors = _anchors(state_store)
    assert anchors.round().stamped == 512
    assert anchors.round().stamped == 1


def test_a_round_never_confirms_a_proof_of_another_digest(state_store):
    # A real, Bitcoin-attested proof stored beside a seal it does not cover.
    state_store.add_seal(_golden_seal())
    state_store.put("anchored_to", "1")
    record = {"bitcoin": None, "ots": OTS["core29"]["pending"], "stamped_at": 1}
    state_store.put_record("ots-pending", "1", json.dumps(record))
    headers = RecordedHeaders({892418: H18})
    anchors = _anchors(state_store, answers=OTS["core29"]["answers"], headers=headers)
    assert anchors.round() == AnchorRound(
        0, 0, 1, "anchor: proof is not over this seal's anchor digest"
    )
    assert anchors.view(1)["bitcoin"] is None
    # Refused before any header is fetched.
    assert headers.asked == []


class _WrongAnswerCalendar:
    """A calendar that answers a timestamp of some other message."""

    def submit(self, digest: bytes, timeout: float | None = None) -> Timestamp:
        return Timestamp(b"\x00" * 32)

    def get_timestamp(
        self, commitment: bytes, timeout: float | None = None
    ) -> Timestamp:
        return Timestamp(b"\x00" * 32)


class _RaisingHeaders:
    """A header source failing with something other than an `AnchorError`."""

    def header(self, height: int) -> bytes:
        raise RuntimeError("socket closed")


def test_a_round_survives_any_calendar_failure(state_store):
    state_store.add_seal(_golden_seal())
    calendars = [_BrokenCalendar(), _WrongAnswerCalendar(), *recorded_aggregators(2)]
    anchors = _anchors(state_store, calendars)
    assert anchors.round() == AnchorRound(1, 0, 1, None)
    kept = anchors.view(1)

    def calendar_for(uri: str) -> Calendar:
        return _BrokenCalendar() if "alice" in uri else _WrongAnswerCalendar()

    again = _anchors(state_store, calendar_for=calendar_for)
    assert again.round() == AnchorRound(0, 0, 1, None)
    assert again.view(1) == kept


def test_a_round_survives_a_header_source_failure(state_store, caplog, monkeypatch):
    _attested_beside_seals(state_store, monkeypatch, 1, PENDING)
    anchors = _anchors(
        state_store, answers=OTS["core29"]["answers"], headers=_RaisingHeaders()
    )
    assert anchors.round() == AnchorRound(0, 0, 1, "anchor: header source unavailable")
    assert "anchor header source failed (RuntimeError)" in caplog.text
    # The upgrade is kept, so the next round does not ask the calendars again.
    assert unb64(anchors.view(1)["ots"]) == UPGRADED


def test_a_round_records_nothing_another_round_recorded_first(state_store):
    state_store.add_seal(_golden_seal())
    held = BlockingCalendar(recorded_aggregators()[0])
    slow = _anchors(state_store, [held, *recorded_aggregators()[1:]])
    outcome = []
    racer = threading.Thread(target=lambda: outcome.append(slow.round()))
    racer.start()
    assert held.entered.wait(5)
    fast = _anchors(state_store)
    assert fast.round() == AnchorRound(1, 0, 1, None)
    kept = fast.view(1)
    held.release.set()
    racer.join(5)
    assert outcome == [AnchorRound(0, 0, 1, None)]
    assert slow.view(1) == kept


def _attested_beside_seals(store, monkeypatch, count, proof=UPGRADED):
    # Only the golden stamp after its upgrade is a real Bitcoin-attested proof
    # over a seal's anchor digest; until then, each seal's digest is CORE.
    monkeypatch.setattr("gate.anchor_public.anchor_digest_of", lambda *_: CORE)
    for seq in range(1, count + 1):
        store.add_seal(_seal(seq, f"{seq:064x}"))
        record = {"ots": base64.b64encode(proof).decode(), "bitcoin": None}
        store.put_record(
            "ots-pending", str(seq), json.dumps(record | {"stamped_at": 1})
        )
    store.put("anchored_to", str(count))


def test_a_bad_lowest_attestation_does_not_block_a_higher_one(state_store, monkeypatch):
    _attested_beside_seals(state_store, monkeypatch, 1)
    headers = RecordedHeaders({892418: FLIPPED, 892421: H21})
    anchors = _anchors(state_store, headers=headers)
    assert anchors.round() == AnchorRound(0, 1, 0, None)
    assert anchors.view(1)["bitcoin"] == {"height": 892421, "header": H21.hex()}
    assert unb64(anchors.view(1)["ots"]) == UPGRADED


def test_a_round_fetches_each_header_once(state_store, monkeypatch):
    _attested_beside_seals(state_store, monkeypatch, 3)
    headers = RecordedHeaders({892421: H21})
    anchors = _anchors(state_store, headers=headers)
    assert anchors.round() == AnchorRound(0, 3, 0, None)
    # 892418 failed once and was not asked again this round.
    assert headers.asked == [892418, 892421]


def test_stuck_proofs_do_not_hold_the_upgrade_window(state_store, monkeypatch):
    stuck = UPGRADE_BATCH + 1
    _attested_beside_seals(state_store, monkeypatch, stuck)
    record = {"ots": OTS["core29"]["pending"], "bitcoin": None, "stamped_at": 1}
    state_store.put_record("ots-pending", str(stuck + 1), json.dumps(record))
    anchors = _anchors(state_store, answers=OTS["core29"]["answers"])
    error = "anchor: header source unavailable"
    assert anchors.round() == AnchorRound(0, 0, stuck + 1, error)
    assert anchors.view(stuck + 1)["ots"] == OTS["core29"]["pending"]
    assert anchors.round() == AnchorRound(0, 0, stuck + 1, error)
    assert unb64(anchors.view(stuck + 1)["ots"]) == UPGRADED


def test_a_corrupt_record_reads_as_no_anchor(state_store, caplog):
    state_store.put_record("ots-pending", "1", "{not json")
    assert _anchors(state_store).view(1) is None
    assert "anchor record unreadable (JSONDecodeError)" in caplog.text


def _crafted_proof(tree: str) -> bytes:
    return bytes.fromhex(MAGIC + DIGEST + tree)


def _varbytes(data: bytes) -> str:
    assert len(data) < 0x80
    return f"{len(data):02x}" + data.hex()


ATTESTED = "00" + "0588960d73d71901" + _varbytes(bytes.fromhex("a0ef36"))


def _pending_at(uri: bytes) -> str:
    return "00" + "83dfe30d2ef90c8e" + _varbytes(bytes.fromhex(_varbytes(uri)))


@pytest.mark.parametrize(
    ("tree", "readable"),
    [
        (ATTESTED, True),
        (_pending_at(b"https://alice.btc.calendar.opentimestamps.org"), True),
        ("08" * 255 + ATTESTED, True),
        ("08" * 256 + ATTESTED, False),
        ("ff" + "08" + ATTESTED + "f001aa" + ATTESTED, True),
        ("ff" + "08" + ATTESTED + "08" + ATTESTED, False),
        ("ff" + "f001aa" + ATTESTED + "f001aa" + ATTESTED, False),
        ("02" + ATTESTED, False),
        ("67" + ATTESTED, False),
        ("f000" + ATTESTED, False),
        (ATTESTED + "00", False),
        (ATTESTED[:-2], False),
        (_pending_at(b"https://a b"), False),
        ("00" + "0102030405060708" + _varbytes(b"any payload"), True),
        ("00" + "0588960d73d71901" + _varbytes(bytes.fromhex("8080808010")), False),
    ],
)
def test_the_desk_reads_a_proof_as_the_explorer_does(tree, readable):
    assert explorer_can_read(_crafted_proof(tree)) is readable


def test_the_desk_refuses_what_the_explorer_refuses_whole():
    assert explorer_can_read(PENDING) and explorer_can_read(UPGRADED)
    assert explorer_can_read(unb64(OTS["golden"]["pending"]))
    assert not explorer_can_read(HELLO)  # ripemd160
    assert not explorer_can_read(UPGRADED[:-1])
    assert not explorer_can_read(b"not a proof")
    wide = "".join(
        "ff" + "f0" + "a01f" + (bytes([i]) * 4000).hex() + ATTESTED for i in range(9)
    )
    assert not explorer_can_read(_crafted_proof(wide + ATTESTED))


class _Crafted:
    """A calendar that answers every call with a timestamp built for its message."""

    def __init__(self, build) -> None:
        self.build = build

    def submit(self, digest: bytes, timeout: float | None = None) -> Timestamp:
        return self.build(digest)

    def get_timestamp(
        self, commitment: bytes, timeout: float | None = None
    ) -> Timestamp:
        return self.build(commitment)


def _foreign_op(op):
    def build(msg):
        stamp_ = Timestamp(msg)
        stamp_.ops.add(op).attestations.add(BitcoinBlockHeaderAttestation(900000))
        return stamp_

    return build


def _deep(ops):
    def build(msg):
        stamp_ = node = Timestamp(msg)
        for _ in range(ops):
            node = node.ops.add(OpSHA256())
        node.attestations.add(BitcoinBlockHeaderAttestation(900000))
        return stamp_

    return build


def _wide(appends, first=0):
    def build(msg):
        stamp_ = Timestamp(msg)
        for i in range(first, first + appends):
            child = stamp_.ops.add(OpAppend(bytes([i]) * 4000))
            child.attestations.add(BitcoinBlockHeaderAttestation(900000))
        return stamp_

    return build


def _dangling(msg):
    stamp_ = Timestamp(msg)
    stamp_.ops.add(OpSHA256())
    stamp_.attestations.add(BitcoinBlockHeaderAttestation(900000))
    return stamp_


# A lone digest's tip sits two operations deep (nonce, sha256): 253 more is the
# deepest the explorer reads.
UNREADABLE = {
    "sha1": _foreign_op(OpSHA1()),
    "keccak256": _foreign_op(OpKECCAK256()),
    "too deep": _deep(254),
    "too large": _wide(9),
    "dangling": _dangling,
}


@pytest.mark.parametrize("build", UNREADABLE.values(), ids=UNREADABLE.keys())
def test_a_stamp_drops_an_answer_the_explorer_cannot_read(build):
    good = recorded_aggregators()[:3]
    (proof,) = stamp([D1], [_Crafted(build), *good], lambda: b"\x01" * 16)
    assert proof == stamp([D1], recorded_aggregators()[:3], lambda: b"\x01" * 16)[0]
    assert explorer_can_read(proof)
    with pytest.raises(AnchorError, match="^anchor: 1 of 2 calendars answered$"):
        stamp([D1], [_Crafted(build), good[0]], lambda: b"\x01" * 16)


def test_a_stamp_keeps_the_deepest_answer_the_explorer_reads():
    (proof,) = stamp(
        [D1], [_Crafted(_deep(253)), *recorded_aggregators()[:1]], lambda: b"\x01" * 16
    )
    assert explorer_can_read(proof)
    assert attested_heights(proof) == [900000]


def test_a_stamp_drops_the_answer_that_would_outgrow_the_explorer():
    first, second = _Crafted(_wide(7)), _Crafted(_wide(2, first=7))
    good = recorded_aggregators()[:2]
    (proof,) = stamp([D1], [first, second, *good], lambda: b"\x01" * 16)
    assert proof == stamp([D1], [first, *good], lambda: b"\x01" * 16)[0]
    assert explorer_can_read(proof)


@pytest.mark.parametrize("build", UNREADABLE.values(), ids=UNREADABLE.keys())
def test_an_upgrade_drops_an_answer_the_explorer_cannot_read(build):
    assert upgrade(PENDING, lambda uri: _Crafted(build)) == PENDING
    calendars = RecordedCalendars(OTS["core29"]["answers"])
    poisoned = sorted(CALENDARS)[0]

    def calendar_for(uri: str) -> Calendar:
        return _Crafted(build) if uri == poisoned else calendars.for_uri(uri)

    def broken_for(uri: str) -> Calendar:
        return _BrokenCalendar() if uri == poisoned else calendars.for_uri(uri)

    upgraded = upgrade(PENDING, calendar_for)
    assert upgraded == upgrade(PENDING, broken_for)
    assert explorer_can_read(upgraded)


def test_a_malformed_stored_seal_does_not_wedge_the_rounds(state_store):
    seal = {**_seal(1, ROOT), "signature": base64.b64encode(bytes(10)).decode()}
    state_store.add_seal(seal)
    record = {"ots": OTS["core29"]["upgraded"], "bitcoin": None, "stamped_at": 1}
    state_store.put_record("ots-pending", "1", json.dumps(record))
    state_store.put("anchored_to", "1")
    anchors = _anchors(state_store, headers=RecordedHeaders({892418: H18}))
    assert anchors.round() == AnchorRound(0, 0, 1, "anchor: proof malformed")
    assert anchors.view(1)["ots"] == OTS["core29"]["upgraded"]
