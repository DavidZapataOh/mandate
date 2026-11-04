"""Public timestamps of registry seals through OpenTimestamps and Bitcoin."""

import base64
import hashlib
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import (
    DetachedTimestampFile,
    Timestamp,
    make_merkle_tree,
)

from gate.registry import Anchor

AGGREGATORS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
)
MIN_CALENDARS = 2
CALENDAR_TIMEOUT_S = 5
HEADER_TIMEOUT_S = 10
NONCE_LEN = 16
MAX_TARGET = 2**180
MAX_PROOF_BYTES = 32768
STAMP_BATCH = 512
UPGRADE_BATCH = 64

_DIGEST_PREFIX = b"mandate-anchor/v1:"


class AnchorError(ValueError):
    """A public timestamp could not be made, upgraded or checked."""


class Calendar(Protocol):
    """An OpenTimestamps calendar or aggregator, as `RemoteCalendar` serves one."""

    def submit(self, digest: bytes, timeout: float | None = None) -> Timestamp:
        """Submit a digest; return the timestamp committing to it."""
        ...

    def get_timestamp(
        self, commitment: bytes, timeout: float | None = None
    ) -> Timestamp:
        """Return the calendar's timestamp for a pending commitment."""
        ...


def anchor_digest(seal: Anchor, gate_public_key: bytes) -> bytes:
    """The digest a desk stamps for one of its seals.

    The bare root is shared by desks with equal entries, so the stamp names the
    desk (its gate key) and the signed seal (id, range, time, root, signature).

    Args:
        seal: The gate-signed registry seal.
        gate_public_key: The gate's raw 32-byte Ed25519 public key.

    Returns:
        sha256 over the domain prefix, the key, the seal's signed bytes and its
        signature.

    Raises:
        ValueError: The key is not 32 bytes or the signature not 64 bytes.
    """
    if len(gate_public_key) != 32:
        raise ValueError("anchor: gate key must be 32 bytes")
    if len(seal.signature) != 64:
        raise ValueError("anchor: seal signature must be 64 bytes")
    return hashlib.sha256(
        _DIGEST_PREFIX + gate_public_key + seal.signable_bytes() + seal.signature
    ).digest()


def anchor_digest_of(view: dict[str, Any], gate_public_key: bytes) -> bytes:
    """`anchor_digest` of a stored seal view (standard-base64 signature).

    Args:
        view: A seal view with keys v, anchor_id, seq_from, seq_to, root, ts and
            signature.
        gate_public_key: The gate's raw 32-byte Ed25519 public key.

    Returns:
        The seal's anchor digest.

    Raises:
        ValueError: The view is malformed, or a length is wrong.
    """
    seal = Anchor(
        v=view["v"],
        anchor_id=view["anchor_id"],
        seq_from=view["seq_from"],
        seq_to=view["seq_to"],
        root=view["root"],
        ts=view["ts"],
        signature=base64.b64decode(view["signature"], validate=True),
    )
    return anchor_digest(seal, gate_public_key)


def _serialized(proof: DetachedTimestampFile) -> bytes:
    ctx = BytesSerializationContext()
    proof.serialize(ctx)
    return bytes(ctx.getbytes())


def _ask(calendar: Calendar, digest: bytes) -> Timestamp | None:
    # A calendar that is down, slow or answers garbage counts as no answer.
    try:
        return calendar.submit(digest, timeout=CALENDAR_TIMEOUT_S)
    except Exception:
        return None


def stamp(
    roots: Sequence[bytes],
    calendars: Sequence[Calendar],
    nonces: Callable[[], bytes],
) -> list[bytes]:
    """Stamp a batch of digests the way `ots stamp` does.

    Each digest gets a nonce appended and is hashed, so a calendar or a proof
    reader learns nothing of the others; the leaves form one merkle tree whose
    tip goes to every calendar, in order.

    Args:
        roots: The 32-byte digests to stamp.
        calendars: The aggregators to submit the tip to.
        nonces: Source of one fresh nonce per digest.

    Returns:
        Each digest's serialized `.ots` proof, in the digests' order.

    Raises:
        ValueError: `roots` is empty.
        AnchorError: Fewer than `MIN_CALENDARS` calendars answered.
    """
    if not roots:
        raise ValueError("anchor: nothing to stamp")
    proofs = [DetachedTimestampFile(OpSHA256(), Timestamp(root)) for root in roots]
    leaves = [
        proof.timestamp.ops.add(OpAppend(nonces())).ops.add(OpSHA256())
        for proof in proofs
    ]
    tip = make_merkle_tree(leaves)
    answered = 0
    for calendar in calendars:
        answer = _ask(calendar, tip.msg)
        if answer is not None:
            tip.merge(answer)
            answered += 1
    if answered < MIN_CALENDARS:
        raise AnchorError(f"anchor: {answered} of {len(calendars)} calendars answered")
    return [_serialized(proof) for proof in proofs]
