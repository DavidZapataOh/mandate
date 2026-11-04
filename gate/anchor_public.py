"""Public timestamps of registry seals through OpenTimestamps and Bitcoin."""

import base64
import hashlib
import re
from collections.abc import Callable, Iterator, Sequence
from typing import Any, Protocol

import httpx2
from opentimestamps.calendar import (
    DEFAULT_CALENDAR_WHITELIST,
    RemoteCalendar,
)
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpPrepend, OpSHA256
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
)
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
BLOCK_SOURCE = "https://blockstream.info/api"

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


class HeaderSource(Protocol):
    """Where 80-byte Bitcoin block headers come from, by height."""

    def header(self, height: int) -> bytes:
        """Return the header of the block at `height`."""
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


_CHECKABLE_OPS = (OpSHA256, OpAppend, OpPrepend)
_HASH_HEX = re.compile(r"[0-9a-f]{64}")
_HEADER_HEX = re.compile(r"[0-9a-f]{160}")


def _parse(proof: bytes) -> DetachedTimestampFile:
    try:
        ctx = BytesDeserializationContext(proof)
        parsed = DetachedTimestampFile.deserialize(ctx)
        ctx.assert_eof()
    except Exception as exc:
        raise AnchorError("anchor: proof malformed") from exc
    return parsed


def _walk(stamp: Timestamp) -> Iterator[Timestamp]:
    yield stamp
    for sub in stamp.ops.values():
        yield from _walk(sub)


def _attested(stamp: Timestamp) -> Iterator[Timestamp]:
    # Like `ots upgrade`: the first stamps down each path that carry attestations.
    if stamp.attestations:
        yield stamp
    else:
        for sub in stamp.ops.values():
            yield from _attested(sub)


def _attestations(stamp: Timestamp) -> set[Any]:
    return {att for _, att in stamp.all_attestations()}


def upgrade(
    proof: bytes,
    calendar_for: Callable[[str], Calendar] = RemoteCalendar,
    cache: dict[bytes, Timestamp | None] | None = None,
) -> bytes:
    """Ask each whitelisted calendar for its pending commitments, as `ots upgrade`.

    Args:
        proof: A serialized `.ots` proof.
        calendar_for: Builds the calendar client for a pending attestation's URI.
        cache: Each commitment's answer (or None) for this round, shared across
            proofs so a batch asks each calendar once per commitment.

    Returns:
        The serialized proof; the same bytes when no calendar had anything new.

    Raises:
        AnchorError: The proof is malformed, or the upgrade made it too large.
    """
    parsed = _parse(proof)
    cache = {} if cache is None else cache
    existing = _attestations(parsed.timestamp)
    changed = False
    for sub in list(_attested(parsed.timestamp)):
        for att in list(sub.attestations):
            if not isinstance(att, PendingAttestation):
                continue
            if att.uri not in DEFAULT_CALENDAR_WHITELIST:
                continue
            if sub.msg in cache:
                answer = cache[sub.msg]
            else:
                try:
                    answer = calendar_for(att.uri).get_timestamp(
                        sub.msg, timeout=CALENDAR_TIMEOUT_S
                    )
                except Exception:
                    # Not found yet, down, slow or garbage: no answer this round.
                    answer = None
                cache[sub.msg] = answer
            if answer is None:
                continue
            new = _attestations(answer) - existing
            if new:
                existing |= new
                sub.merge(answer)
                changed = True
    if not changed:
        return proof
    out = _serialized(parsed)
    if len(out) > MAX_PROOF_BYTES:
        raise AnchorError("anchor: proof too large")
    return out


def attested_heights(proof: bytes) -> list[int]:
    """Every Bitcoin block height the proof is attested in, ascending.

    Args:
        proof: A serialized `.ots` proof.

    Returns:
        The de-duplicated heights.

    Raises:
        AnchorError: The proof is malformed.
    """
    parsed = _parse(proof)
    return sorted(
        {
            int(att.height)
            for _, att in parsed.timestamp.all_attestations()
            if isinstance(att, BitcoinBlockHeaderAttestation)
        }
    )


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def block_hash(header: bytes) -> str:
    """A block header's hash in display order (as block explorers print it)."""
    return _sha256d(header)[::-1].hex()


def _target(bits: int) -> int:
    exponent, mantissa = bits >> 24, bits & 0x007FFFFF
    if bits & 0x00800000 or mantissa == 0:
        return 0
    if exponent < 3:
        return mantissa >> 8 * (3 - exponent)
    return mantissa << 8 * (exponent - 3)


def confirm(proof: bytes, digest: bytes, height: int, header: bytes) -> int:
    """Check offline that a proof over `digest` is committed in a block header.

    The header is trusted only through its own proof of work and a work floor;
    that the block is in the main chain at `height` is left to the reader.

    Args:
        proof: A serialized `.ots` proof.
        digest: The seal's anchor digest (never a bare root).
        height: The Bitcoin block height the proof attests.
        header: That block's 80-byte header.

    Returns:
        The header's time (`nTime`), in unix seconds.

    Raises:
        AnchorError: The first check that fails, in the documented order.
    """
    parsed = _parse(proof)
    if not isinstance(parsed.file_hash_op, OpSHA256) or (
        bytes(parsed.file_digest) != digest
    ):
        raise AnchorError("anchor: proof is not over this seal's anchor digest")
    for stamp_ in _walk(parsed.timestamp):
        if not all(isinstance(op, _CHECKABLE_OPS) for op in stamp_.ops):
            raise AnchorError(
                "anchor: proof uses an operation the explorer cannot check"
            )
    roots = {
        bytes(msg)
        for msg, att in parsed.timestamp.all_attestations()
        if isinstance(att, BitcoinBlockHeaderAttestation) and att.height == height
    }
    if not roots:
        raise AnchorError(f"anchor: proof names no Bitcoin block {height}")
    if len(header) != 80:
        raise AnchorError("anchor: a block header is 80 bytes")
    target = _target(int.from_bytes(header[72:76], "little"))
    if int.from_bytes(_sha256d(header), "little") > target:
        raise AnchorError("anchor: header misses its proof-of-work target")
    if target > MAX_TARGET:
        raise AnchorError("anchor: header is below the work floor")
    if header[36:68] not in roots:
        raise AnchorError("anchor: block header does not hold the proof's merkle root")
    return int.from_bytes(header[68:72], "little")


class EsploraHeaders:
    """Block headers by height from an Esplora API, trusted for availability only."""

    def __init__(
        self, http_client: httpx2.Client | None = None, base: str = BLOCK_SOURCE
    ) -> None:
        """Bind the source.

        Args:
            http_client: The HTTP client; one with `HEADER_TIMEOUT_S` if omitted.
            base: The Esplora API base URL.
        """
        self._http = http_client or httpx2.Client(timeout=HEADER_TIMEOUT_S)
        self._base = base

    def _get(self, path: str, shape: re.Pattern[str]) -> str:
        try:
            response = self._http.get(f"{self._base}{path}")
        except httpx2.HTTPError as exc:
            raise AnchorError("anchor: header source unavailable") from exc
        if response.status_code != 200 or not shape.fullmatch(response.text):
            raise AnchorError("anchor: header source unavailable")
        return str(response.text)

    def header(self, height: int) -> bytes:
        """Return the 80-byte header of the block at `height`.

        Args:
            height: The Bitcoin block height.

        Returns:
            The raw header.

        Raises:
            AnchorError: The source failed, or answered a header of another block.
        """
        block = self._get(f"/block-height/{height}", _HASH_HEX)
        header = bytes.fromhex(self._get(f"/block/{block}/header", _HEADER_HEX))
        if block_hash(header) != block:
            raise AnchorError("anchor: header source answered another block")
        return header
