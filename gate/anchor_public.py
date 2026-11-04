"""Public timestamps of registry seals through OpenTimestamps and Bitcoin."""

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
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
from gate.state import StateStore

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
_PENDING = "ots-pending"
_CONFIRMED = "ots"
_ANCHORED_TO = "anchored_to"

_log = logging.getLogger(__name__)


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


def _answer_for(msg: bytes, answer: object) -> Timestamp | None:
    # A timestamp of another message cannot be merged; it is no answer.
    if isinstance(answer, Timestamp) and bytes(answer.msg) == msg:
        return answer
    return None


def _ask(calendar: Calendar, digest: bytes) -> Timestamp | None:
    # A calendar that is down, slow or answers garbage counts as no answer.
    try:
        return _answer_for(digest, calendar.submit(digest, timeout=CALENDAR_TIMEOUT_S))
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
        AnchorError: Fewer than `MIN_CALENDARS` calendars answered with a
            proof the explorer can read.
    """
    if not roots:
        raise ValueError("anchor: nothing to stamp")
    salts = [nonces() for _ in roots]
    tip_msg = _stamped(roots, salts, [])[1]
    kept: list[Timestamp] = []
    out: list[bytes] = []
    for calendar in calendars:
        answer = _ask(calendar, tip_msg)
        if answer is None:
            continue
        trial = _readable(roots, salts, [*kept, answer])
        if trial is not None:
            kept.append(answer)
            out = trial
    if len(kept) < MIN_CALENDARS:
        raise AnchorError(f"anchor: {len(kept)} of {len(calendars)} calendars answered")
    return out


def _readable(
    roots: Sequence[bytes], salts: Sequence[bytes], answers: Sequence[Timestamp]
) -> list[bytes] | None:
    # An answer the explorer could not read would fail every receipt of the
    # batch for good, so it counts as no answer.
    try:
        proofs = [_serialized(p) for p in _stamped(roots, salts, answers)[0]]
    except Exception:
        return None
    return proofs if all(explorer_can_read(p) for p in proofs) else None


def _stamped(
    roots: Sequence[bytes], salts: Sequence[bytes], answers: Sequence[Timestamp]
) -> tuple[list[DetachedTimestampFile], bytes]:
    # Rebuilt per answer, so a refused answer leaves no trace in the proofs.
    proofs = [DetachedTimestampFile(OpSHA256(), Timestamp(root)) for root in roots]
    leaves = [
        proof.timestamp.ops.add(OpAppend(salt)).ops.add(OpSHA256())
        for proof, salt in zip(proofs, salts, strict=True)
    ]
    tip = make_merkle_tree(leaves)
    for answer in answers:
        tip.merge(answer)
    return proofs, bytes(tip.msg)


_OTS_MAGIC = bytes.fromhex(
    "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294"
)
_PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
_BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
_MAX_DEPTH = 256
_MAX_ARG = 4096
_MAX_PAYLOAD = 8192
_MAX_URI = 1000
_MAX_HEIGHT = 0xFFFFFFFF
_URI_CHARS = re.compile(r"[A-Za-z0-9._/:-]*")


class _UnreadableError(Exception):
    pass


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    @property
    def done(self) -> bool:
        return self._at == len(self._data)

    def take(self, n: int) -> bytes:
        if self._at + n > len(self._data):
            raise _UnreadableError
        out = self._data[self._at : self._at + n]
        self._at += n
        return out

    def byte(self) -> int:
        return self.take(1)[0]

    def varuint(self) -> int:
        value = 0
        for i in range(9):
            b = self.byte()
            value |= (b & 0x7F) << (7 * i)
            if not b & 0x80:
                return value
        raise _UnreadableError

    def varbytes(self, most: int, least: int = 0) -> bytes:
        n = self.varuint()
        if not least <= n <= most:
            raise _UnreadableError
        return self.take(n)


def _check_attestation(tag: bytes, payload: bytes) -> None:
    r = _Reader(payload)
    if tag == _PENDING_TAG:
        try:
            uri = r.varbytes(_MAX_URI).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _UnreadableError from exc
        if not _URI_CHARS.fullmatch(uri):
            raise _UnreadableError
    elif tag == _BITCOIN_TAG:
        if r.varuint() > _MAX_HEIGHT:
            raise _UnreadableError
    else:
        return
    if not r.done:
        raise _UnreadableError


def _check_tree(r: _Reader, msg_len: int, depth: int) -> None:
    if depth >= _MAX_DEPTH:
        raise _UnreadableError
    seen: set[bytes] = set()
    tag = r.byte()
    while tag == 0xFF:
        _check_branch(r, r.byte(), msg_len, depth, seen)
        tag = r.byte()
    _check_branch(r, tag, msg_len, depth, seen)


def _check_branch(
    r: _Reader, tag: int, msg_len: int, depth: int, seen: set[bytes]
) -> None:
    if tag == 0x00:
        kind = r.take(8)
        _check_attestation(kind, r.varbytes(_MAX_PAYLOAD))
        return
    if tag == 0x08:
        op, next_len = b"\x08", 32
    elif tag in (0xF0, 0xF1):
        arg = r.varbytes(_MAX_ARG, 1)
        op, next_len = bytes([tag]) + arg, msg_len + len(arg)
    else:
        raise _UnreadableError
    if op in seen or next_len > _MAX_ARG:
        raise _UnreadableError
    seen.add(op)
    _check_tree(r, next_len, depth + 1)


def explorer_can_read(proof: bytes) -> bool:
    """Whether the explorer's proof reader accepts these `.ots` bytes.

    The same rules as the console's `readOts`: size, magic, version, a
    sha256 file digest, sha256/append/prepend only, nesting, a repeated
    operation, argument, result and attestation limits, no trailing bytes.

    Args:
        proof: A serialized `.ots` proof.

    Returns:
        True when the explorer would read it, else False.
    """
    if len(proof) > MAX_PROOF_BYTES or not proof.startswith(_OTS_MAGIC):
        return False
    r = _Reader(proof[len(_OTS_MAGIC) :])
    try:
        if r.varuint() != 1 or r.byte() != 0x08:
            return False
        r.take(32)
        _check_tree(r, 32, 0)
    except _UnreadableError:
        return False
    return r.done


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
        The serialized proof; the same bytes when no calendar had anything new
        the explorer can read.

    Raises:
        AnchorError: The proof is malformed.
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
                    answer = _answer_for(
                        sub.msg,
                        calendar_for(att.uri).get_timestamp(
                            sub.msg, timeout=CALENDAR_TIMEOUT_S
                        ),
                    )
                except Exception:
                    # Not found yet, down, slow or garbage: no answer this round.
                    answer = None
                cache[sub.msg] = answer
            if answer is None:
                continue
            new = _attestations(answer) - existing
            if new and _merged_readably(parsed, sub, answer):
                existing |= new
                changed = True
    return _serialized(parsed) if changed else proof


def _merged_readably(
    parsed: DetachedTimestampFile, sub: Timestamp, answer: Timestamp
) -> bool:
    # An answer the explorer could not read would fail the receipt for good,
    # so it counts as no answer and `sub` is put back as it was.
    ctx = BytesSerializationContext()
    sub.serialize(ctx)
    saved = Timestamp.deserialize(BytesDeserializationContext(ctx.getbytes()), sub.msg)
    try:
        sub.merge(answer)
        readable = explorer_can_read(_serialized(parsed))
    except Exception:
        readable = False
    if not readable:
        sub.attestations, sub.ops = saved.attestations, saved.ops
    return readable


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


@dataclass(frozen=True)
class AnchorRound:
    """What one round of `PublicAnchors` did.

    Attributes:
        stamped: Seals newly submitted to the calendars.
        confirmed: Proofs newly confirmed against a Bitcoin block header.
        pending: Proofs still without a confirmed Bitcoin block.
        error: The first `AnchorError` of the round, or None.
    """

    stamped: int
    confirmed: int
    pending: int
    error: str | None

    def view(self) -> dict[str, Any]:
        """The round as JSON-ready fields, in declaration order."""
        return {
            "stamped": self.stamped,
            "confirmed": self.confirmed,
            "pending": self.pending,
            "error": self.error,
        }


def _nonce() -> bytes:
    return os.urandom(NONCE_LEN)


def _record(proof: bytes, bitcoin: dict[str, Any] | None, stamped_at: int) -> str:
    return json.dumps(
        {
            "ots": base64.b64encode(proof).decode(),
            "bitcoin": bitcoin,
            "stamped_at": stamped_at,
        },
        separators=(",", ":"),
    )


class PublicAnchors:
    """Stamps a durable store's seals and upgrades their proofs to Bitcoin.

    Calendars and the block source are called with no lock held, the store's
    included: a round reads what to do, calls out, then records the outcome in
    one transaction, recording nothing another round already recorded.
    """

    def __init__(
        self,
        state: StateStore,
        gate_public_key: bytes,
        calendars: Sequence[Calendar],
        headers: HeaderSource,
        clock: Callable[[], int],
        *,
        calendar_for: Callable[[str], Calendar] = RemoteCalendar,
        nonces: Callable[[], bytes] = _nonce,
    ) -> None:
        """Bind the store and the third parties.

        Args:
            state: The durable store holding the seals and their proofs.
            gate_public_key: The gate's raw 32-byte Ed25519 public key.
            calendars: The aggregators new seals are submitted to.
            headers: Where Bitcoin block headers come from.
            clock: Current unix time in seconds.
            calendar_for: Builds the calendar client for a pending URI.
            nonces: Source of one 16-byte nonce per stamped seal.
        """
        self._state = state
        self._gate_public_key = gate_public_key
        self._calendars = list(calendars)
        self._headers = headers
        self._clock = clock
        self._calendar_for = calendar_for
        self._nonces = nonces
        self._rounds = threading.Lock()

    def round(self) -> AnchorRound:
        """Stamp new seals, upgrade pending proofs, record confirmed ones.

        One round runs at a time; a second caller waits for the first
        (`try_round` does not).

        Returns:
            What the round did; an `AnchorError` is reported, not raised.
        """
        with self._rounds:
            return self._round()

    def try_round(self) -> AnchorRound | None:
        """Run a round like `round`, unless one is already running.

        Returns:
            What the round did, or None when another round holds the slot.
        """
        if not self._rounds.acquire(blocking=False):
            return None
        try:
            return self._round()
        finally:
            self._rounds.release()

    def _round(self) -> AnchorRound:
        stamped, error = self._stamp()
        confirmed, upgrade_error = self._upgrade()
        pending = len(self._state.records(_PENDING))
        return AnchorRound(stamped, confirmed, pending, error or upgrade_error)

    def _anchored_to(self) -> int:
        return int(self._state.get(_ANCHORED_TO) or 0)

    def _stamp(self) -> tuple[int, str | None]:
        mark = self._anchored_to()
        views = self._state.seals_after(mark, STAMP_BATCH)
        if not views:
            return 0, None
        digests = [anchor_digest_of(v, self._gate_public_key) for v in views]
        try:
            proofs = stamp(digests, self._calendars, self._nonces)
        except AnchorError as exc:
            return 0, str(exc)
        now = self._clock()
        with self._state.transaction():
            if self._anchored_to() != mark:
                return 0, None
            for view, proof in zip(views, proofs, strict=True):
                self._state.put_record(
                    _PENDING, str(view["seq_to"]), _record(proof, None, now)
                )
            self._state.put(_ANCHORED_TO, str(views[-1]["seq_to"]))
        return len(views), None

    def _upgrade(self) -> tuple[int, str | None]:
        cache: dict[bytes, Timestamp | None] = {}
        headers: dict[int, bytes | AnchorError] = {}
        confirmed, error = 0, None
        for key, value in self._state.records(_PENDING)[:UPGRADE_BATCH]:
            try:
                confirmed += self._upgrade_one(key, value, cache, headers)
            except AnchorError as exc:
                error = error or str(exc)
        return confirmed, error

    def _header(self, height: int, headers: dict[int, bytes | AnchorError]) -> bytes:
        # Proofs of one stamp share their heights: each is fetched once a
        # round, and a failure is not retried until the next round.
        if height not in headers:
            try:
                headers[height] = self._headers.header(height)
            except AnchorError as exc:
                headers[height] = exc
            except Exception as exc:
                _log.warning("anchor header source failed (%s)", type(exc).__name__)
                headers[height] = AnchorError("anchor: header source unavailable")
        found = headers[height]
        if isinstance(found, AnchorError):
            raise found
        return found

    def _digest(self, seq_to: int, proof: bytes) -> bytes:
        # Recomputed from the stored seal, never read from the proof, and
        # checked before any header is fetched for it.
        found = self._state.seals_after(seq_to - 1, 1)
        parsed = _parse(proof)
        if not found or found[0]["seq_to"] != seq_to:
            raise AnchorError("anchor: proof is not over this seal's anchor digest")
        try:
            digest = anchor_digest_of(found[0], self._gate_public_key)
        except (ValueError, KeyError, TypeError) as exc:
            # One unreadable seal must not stop every other proof's upgrade.
            raise AnchorError("anchor: proof malformed") from exc
        if (
            not isinstance(parsed.file_hash_op, OpSHA256)
            or bytes(parsed.file_digest) != digest
        ):
            raise AnchorError("anchor: proof is not over this seal's anchor digest")
        return digest

    def _confirmed(
        self,
        key: str,
        proof: bytes,
        heights: list[int],
        headers: dict[int, bytes | AnchorError],
    ) -> dict[str, Any]:
        # A bad attestation (a reorged block, a broken calendar) must not hide
        # a good one at a higher height: the lowest that confirms wins.
        digest = self._digest(int(key), proof)
        failed = AnchorError("anchor: proof attests nothing")
        for height in heights:
            try:
                header = self._header(height, headers)
                confirm(proof, digest, height, header)
            except AnchorError as exc:
                failed = exc
                continue
            return {"height": height, "header": header.hex()}
        raise failed

    def _upgrade_one(
        self,
        key: str,
        value: str,
        cache: dict[bytes, Timestamp | None],
        headers: dict[int, bytes | AnchorError],
    ) -> int:
        proof: bytes | None = None
        upgraded: bytes | None = None
        bitcoin, failed = None, None
        try:
            try:
                record = json.loads(value)
                proof = base64.b64decode(record["ots"], validate=True)
                stamped_at = int(record["stamped_at"])
            except (ValueError, KeyError, TypeError, binascii.Error) as exc:
                raise AnchorError("anchor: proof malformed") from exc
            upgraded = upgrade(proof, self._calendar_for, cache)
            heights = attested_heights(upgraded)
            if heights:
                bitcoin = self._confirmed(key, upgraded, heights, headers)
        except AnchorError as exc:
            failed = exc
        with self._state.transaction():
            if self._state.record(_PENDING, key) != value:
                return 0
            if bitcoin is not None and upgraded is not None:
                self._state.put_record(
                    _CONFIRMED, key, _record(upgraded, bitcoin, stamped_at)
                )
                self._state.drop_record(_PENDING, key)
            else:
                # Re-inserted at the back, so proofs that stay stuck cannot
                # hold the upgrade window; an upgrade is kept, so the next
                # round does not ask the calendars again.
                kept = value
                if upgraded is not None and upgraded != proof:
                    kept = _record(upgraded, None, stamped_at)
                self._state.drop_record(_PENDING, key)
                self._state.put_record(_PENDING, key, kept)
        if failed is not None:
            raise failed
        return 0 if bitcoin is None else 1

    def view(self, seq_to: int) -> dict[str, Any] | None:
        """The receipt's `public_anchor` for the seal ending at `seq_to`.

        Args:
            seq_to: The last sequence number the seal covers.

        Returns:
            `{"v": 1, "ots": ..., "bitcoin": ...}`, confirmed proof first, or
            None while the seal is not stamped.
        """
        for kind in (_CONFIRMED, _PENDING):
            value = self._state.record(kind, str(seq_to))
            if value is None:
                continue
            try:
                record = json.loads(value)
                return {"v": 1, "ots": record["ots"], "bitcoin": record["bitcoin"]}
            except (ValueError, KeyError, TypeError) as exc:
                # Absent never reads as a pass in the explorer.
                _log.warning("anchor record unreadable (%s)", type(exc).__name__)
        return None
