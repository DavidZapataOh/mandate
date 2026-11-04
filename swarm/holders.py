"""Paired holder devices: their keys under opaque ids, durable when a store exists."""

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gate.state import StateStore

MAX_HOLDERS = 16

_KIND = "holder"
_LEGACY = "holders"
_UNPAIR_PREFIX = b"holder-unpair/v1:"
_KEY_LEN = 32
_SIGNATURE_LEN = 64


def fingerprint(public_key: bytes) -> str:
    """Short hex fingerprint a person can compare across two screens.

    Args:
        public_key: Raw Ed25519 public key.

    Returns:
        The first 16 hex digits of the key's SHA-256.
    """
    return hashlib.sha256(public_key).hexdigest()[:16]


def unpair_bytes(public_key: bytes) -> bytes:
    """Pinned bytes a paired device signs to retire its own key.

    A retired key never pairs again, so a replayed request changes nothing and
    the message needs no nonce.

    Args:
        public_key: Raw Ed25519 public key of the device.

    Returns:
        `holder-unpair/v1:` followed by the key in standard base64.
    """
    return _UNPAIR_PREFIX + base64.b64encode(public_key)


def verify_unpair(public_key: bytes, signature: bytes) -> bool:
    """True when the key signed its own unpair request.

    Args:
        public_key: Raw 32-byte Ed25519 public key of the device.
        signature: 64-byte Ed25519 signature over `unpair_bytes(public_key)`.

    Returns:
        False for a key not 32 bytes, a signature not 64 bytes, or a failed
        verify.
    """
    if len(public_key) != _KEY_LEN or len(signature) != _SIGNATURE_LEN:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, unpair_bytes(public_key)
        )
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass
class _Holder:
    key: bytes
    paired: bool
    number: int


class HolderRegistry:
    """Paired holder keys under opaque ids; a key that ever paired never pairs again.

    Callers hold the desk lock; the registry adds none of its own.

    Args:
        ids: Source of fresh holder ids; an id already taken is drawn again.
        state: Durable store holding one record per holder; None keeps the
            registry in memory. A legacy `holders` key list in the store is
            paired once, in list order, and then emptied.
        max_paired: Bound on holders paired at once.

    Raises:
        ValueError: If a stored holder record is malformed (KeyError or
            TypeError when it lacks a field or is not an object).
    """

    def __init__(
        self,
        ids: Callable[[], str],
        state: StateStore | None = None,
        max_paired: int = MAX_HOLDERS,
    ) -> None:
        self._ids = ids
        self._state = state
        self._max_paired = max_paired
        self._holders: dict[str, _Holder] = {}
        if state is not None:
            self._load(state)

    def _load(self, state: StateStore) -> None:
        stored = []
        for holder_id, text in state.records(_KIND):
            value = json.loads(text)
            key = base64.b64decode(value["key"], validate=True)
            number, paired = value["number"], value["paired"]
            if (
                len(key) != _KEY_LEN
                or type(number) is not int
                or type(paired) is not bool
            ):
                raise ValueError("holder record malformed")
            stored.append((number, holder_id, key, paired))
        # A record rewritten on unpair moves to the end; the number keeps order.
        for number, holder_id, key, paired in sorted(stored):
            self._holders[holder_id] = _Holder(key, paired, number)
        legacy = json.loads(state.get(_LEGACY) or "[]")
        with state.transaction():
            for text in legacy:
                self.pair(base64.b64decode(text))
            if legacy:
                state.put(_LEGACY, "[]")

    def _save(self, holder_id: str, holder: _Holder) -> None:
        if self._state is None:
            return
        value = {
            "key": base64.b64encode(holder.key).decode("ascii"),
            "number": holder.number,
            "paired": holder.paired,
        }
        self._state.put_record(_KIND, holder_id, json.dumps(value, sort_keys=True))

    @property
    def paired_keys(self) -> tuple[bytes, ...]:
        """Keys paired now, in pairing order."""
        return tuple(h.key for h in self._holders.values() if h.paired)

    @property
    def all_keys(self) -> tuple[bytes, ...]:
        """Every key that ever paired, in pairing order."""
        return tuple(h.key for h in self._holders.values())

    @property
    def paired(self) -> tuple[tuple[str, bytes], ...]:
        """`(holder id, key)` of every holder paired now, in pairing order."""
        return tuple((i, h.key) for i, h in self._holders.items() if h.paired)

    def pair(self, public_key: bytes) -> str | None:
        """Pair a new holder key.

        Args:
            public_key: Raw Ed25519 public key of the device.

        Returns:
            The new holder id; None when the key paired before or every slot
            is taken.
        """
        if any(h.key == public_key for h in self._holders.values()):
            return None
        if len(self.paired_keys) >= self._max_paired:
            return None
        holder_id = self._ids()
        while holder_id in self._holders:
            holder_id = self._ids()
        holder = _Holder(public_key, True, len(self._holders) + 1)
        # Written first: a failed write leaves memory as the store has it.
        self._save(holder_id, holder)
        self._holders[holder_id] = holder
        return holder_id

    def unpair(self, holder_id: str) -> bool:
        """Retire a paired holder; its key stays known so it never pairs again.

        Args:
            holder_id: Id `pair` returned.

        Returns:
            True when the holder was paired; False for an unknown id or one
            already unpaired.
        """
        holder = self._holders.get(holder_id)
        if holder is None or not holder.paired:
            return False
        retired = _Holder(holder.key, False, holder.number)
        self._save(holder_id, retired)
        self._holders[holder_id] = retired
        return True

    def key_of(self, holder_id: str) -> bytes | None:
        """Key of a holder paired now, or None."""
        holder = self._holders.get(holder_id)
        return holder.key if holder is not None and holder.paired else None

    def key_ever(self, holder_id: str) -> bytes | None:
        """Key of a holder that ever paired, or None."""
        holder = self._holders.get(holder_id)
        return holder.key if holder is not None else None

    def holder_of(self, public_key: bytes) -> str | None:
        """Id of the holder paired now under this key, or None."""
        return next(
            (i for i, h in self._holders.items() if h.paired and h.key == public_key),
            None,
        )
