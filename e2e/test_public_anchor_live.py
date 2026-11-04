"""Live OpenTimestamps, Bitcoin Core and block-source answers for offline tests."""

import base64
import hashlib
import json
import os

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from opentimestamps.calendar import DEFAULT_CALENDAR_WHITELIST, RemoteCalendar
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
)
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from gate.anchor_public import stamp
from gate.conftest import OTS, OTS_FILE

GOLDEN = OTS_FILE.parent / "receipt.json"
GATE_KEY = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
CORE29 = "https://bitcoincore.org/bin/bitcoin-core-29.0/SHA256SUMS.ots"
HELLO = (
    "https://raw.githubusercontent.com/opentimestamps/opentimestamps-client"
    "/master/examples/hello-world.txt.ots"
)
ESPLORA = "https://blockstream.info/api"
AGGREGATORS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
)
ROOT = "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87"
CORE29_DIGEST = "94ec151f452a221393d08f6b02fb30baacbeb59f194611f49069e7f5509b46fe"
HELLO_DIGEST = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _bytes(stamp):
    ctx = BytesSerializationContext()
    stamp.serialize(ctx)
    return ctx.getbytes()


def _pending_stamps(stamp):
    if stamp.attestations:
        yield stamp
    for sub in stamp.ops.values():
        yield from _pending_stamps(sub)


def _upgraded(pending):
    """What `ots upgrade` does, keeping every calendar answer."""
    proof = DetachedTimestampFile.deserialize(BytesDeserializationContext(pending))
    answers = {}
    for node in list(_pending_stamps(proof.timestamp)):
        for att in list(node.attestations):
            if isinstance(att, PendingAttestation) and (
                att.uri in DEFAULT_CALENDAR_WHITELIST
            ):
                got = RemoteCalendar(att.uri).get_timestamp(node.msg, timeout=10)
                answer = _b64(_bytes(got))
                answers[node.msg.hex()] = {"uri": att.uri, "answer": answer}
                node.merge(got)
    return _bytes(proof), answers


def _header(http, height):
    block = http.get(f"{ESPLORA}/block-height/{height}").text
    return http.get(f"{ESPLORA}/block/{block}/header").text


def _seal_bytes(seal):
    """The seal's signed bytes, rebuilt from its JSON fields by hand."""
    fields = [
        seal["anchor_id"], seal["root"], seal["seq_from"], seal["seq_to"],
        seal["ts"], seal["v"],
    ]  # fmt: skip
    packed = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return b"anchor/v1:" + packed.encode("ascii")


def _desk_digest(gate_public, signed, signature):
    return hashlib.sha256(
        b"mandate-anchor/v1:" + gate_public + signed + signature
    ).digest()


def _digests():
    """The golden seal's digest, and the same seal signed by another desk."""
    seal = json.loads(GOLDEN.read_text())["registry"]["seal"]
    signed = _seal_bytes(seal)
    golden = _desk_digest(
        base64.b64decode(GATE_KEY), signed, base64.b64decode(seal["signature"])
    )
    other = Ed25519PrivateKey.from_private_bytes(b"\x03" * 32)
    other_public = other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    foreign = _desk_digest(other_public, signed, other.sign(signed))
    return golden, foreign, other_public


def _stamp(digest):
    proof = DetachedTimestampFile(OpSHA256(), Timestamp(digest))
    tip = proof.timestamp.ops.add(OpAppend(os.urandom(16))).ops.add(OpSHA256())
    answers = {}
    for url in AGGREGATORS:
        got = RemoteCalendar(url).submit(tip.msg, timeout=5)
        answers[url] = _b64(_bytes(got))
        tip.merge(got)
    return _bytes(proof), answers


@pytest.mark.live
def test_capture_public_anchor_fixtures():
    http = httpx2.Client(timeout=20, follow_redirects=True)
    core = http.get(CORE29).content
    hello = http.get(HELLO).content
    assert hashlib.sha256(core).hexdigest().startswith("e91f4c5104cce1b4")
    assert hashlib.sha256(hello).hexdigest().startswith("be61ecb940db2e4a")
    upgraded, answers = _upgraded(core)
    assert hashlib.sha256(upgraded).hexdigest().startswith("ed42bc6232526a17")
    headers = {str(h): _header(http, h) for h in (892418, 892421)}
    hello_header = _header(http, 358391)
    if os.environ.get("MANDATE_CAPTURE") != "1":
        # Drift check: the deterministic answers must still be the recorded ones.
        assert answers == OTS["core29"]["answers"]
        assert headers == OTS["core29"]["headers"]
        assert hello_header == OTS["hello2015"]["header"]
        return
    golden, foreign, other_public = _digests()
    pending, aggregators = _stamp(golden)
    foreign_pending, _ = _stamp(foreign)
    bare_pending, _ = _stamp(bytes.fromhex(ROOT))
    fixture = {
        "aggregators": aggregators,
        "core29": {
            "answers": answers,
            "digest": CORE29_DIGEST,
            "headers": headers,
            "pending": _b64(core),
            "upgraded": _b64(upgraded),
        },
        "bare": {"pending": _b64(bare_pending)},
        "foreign": {
            "digest": foreign.hex(),
            "gate_key": _b64(other_public),
            "pending": _b64(foreign_pending),
        },
        "golden": {
            "bitcoin": None,
            "confirmed": None,
            "digest": golden.hex(),
            "pending": _b64(pending),
            "root": ROOT,
        },
        "hello2015": {
            "digest": HELLO_DIGEST,
            "header": hello_header,
            "proof": _b64(hello),
        },
    }
    OTS_FILE.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n")


@pytest.mark.live
def test_stamp_reaches_the_public_calendars():
    root = os.urandom(32)
    calendars = [RemoteCalendar(url) for url in AGGREGATORS]
    (proof,) = stamp([root], calendars, lambda: os.urandom(16))
    read = DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))
    assert read.file_digest == root
    assert len(list(read.timestamp.all_attestations())) >= 2
