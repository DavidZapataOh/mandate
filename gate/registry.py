"""Append-only Merkle receipt log with inclusion proofs."""

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

EMPTY_ROOT = hashlib.sha256(b"registry/v1:empty").hexdigest()

_LEAF_PREFIX = b"leaf/v1:"
_NODE_PREFIX = b"node/v1:"
_ANCHOR_PREFIX = b"anchor/v1:"
_ENTRY_KINDS = frozenset({"execution", "denial", "anchor", "settlement", "return"})
_DIGEST_LEN = 32
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_MISMATCH = "state: registry entries do not match their seals"
_UNSEALED = "state: registry entries past the last seal"

if TYPE_CHECKING:
    from gate.state import StateStore


@dataclass(frozen=True)
class LogEntry:
    """One appended receipt: sequence number, kind, and body."""

    seq: int
    kind: str
    body: str


@dataclass(frozen=True)
class InclusionProof:
    """Merkle inclusion proof for one entry (hex-encoded hashes)."""

    seq: int
    leaves: int
    leaf: str
    siblings: tuple[str, ...]
    root: str


@dataclass(frozen=True)
class Anchor:
    """Signed seal over a contiguous sequence range of the log."""

    v: int
    anchor_id: str
    seq_from: int
    seq_to: int
    root: str
    ts: int
    signature: bytes

    def signable_bytes(self) -> bytes:
        """Domain-separated compact encoding covered by the signature."""
        payload = json.dumps(
            [self.anchor_id, self.root, self.seq_from, self.seq_to, self.ts, self.v],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return _ANCHOR_PREFIX + payload


def _leaf_hash(entry: LogEntry) -> bytes:
    """Leaf digest over the entry's compact JSON encoding."""
    payload = json.dumps(
        {"body": entry.body, "kind": entry.kind, "seq": entry.seq},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(_LEAF_PREFIX + payload).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """Interior node digest over two raw child digests."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _parent_level(level: list[bytes]) -> list[bytes]:
    """Hash pairs upward, duplicating the odd node out."""
    if len(level) % 2 == 1:
        level = [*level, level[-1]]
    return [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]


def _tree_root(leaves: list[bytes]) -> bytes:
    """Reduce leaf digests to the root digest (non-empty input)."""
    level = leaves
    while len(level) > 1:
        level = _parent_level(level)
    return level[0]


class Registry:
    """Append-only log of execution, denial and reasoning-anchor entries."""

    def __init__(
        self,
        max_entries: int = 100000,
        keypair: tuple[bytes, bytes] | None = None,
        state: "StateStore | None" = None,
    ) -> None:
        """Create a registry capped at max_entries entries.

        Args:
            max_entries: Budget on appended entries.
            keypair: Raw Ed25519 (private, public) key pair that signs seals.
            state: Durable store to load the log from and write it through to;
                None keeps the log in memory only. Its writer must seal each
                append in the same transaction as the append.

        Raises:
            ValueError: A stored seal does not verify with the keypair's public
                half, the stored entries do not match the stored seals, or
                entries follow the last seal.
        """
        self._max_entries = max_entries
        self._keypair = keypair
        self._state = state
        self._entries: list[LogEntry] = []
        self._anchors: list[Anchor] = []
        self._last_anchored = 0
        if state is not None:
            self._load(state)

    def _load(self, state: "StateStore") -> None:
        """Adopt the stored log after checking it; nothing is re-signed.

        The newest seal must cover every stored entry: a writer that seals
        each append in the same transaction never leaves an unsealed tail.
        """
        entries = state.entries()
        if any(entry.seq != n for n, entry in enumerate(entries, 1)):
            raise ValueError(_MISMATCH)
        anchors = [_anchor_of(view) for view in state.seals()]
        public = self._keypair[1] if self._keypair is not None else None
        if anchors and (
            public is None or not all(verify_anchor(a, public) for a in anchors)
        ):
            raise ValueError("state: seal does not verify")
        leaves = [_leaf_hash(entry) for entry in entries]
        last = 0
        for anchor in anchors:
            if (
                anchor.seq_from != last + 1
                or not anchor.seq_from <= anchor.seq_to <= len(leaves)
                or anchor.root != _tree_root(leaves[: anchor.seq_to]).hex()
            ):
                raise ValueError(_MISMATCH)
            last = anchor.seq_to
        # Every append is sealed in the same commit, so a stored entry no
        # seal covers was written by something other than this registry.
        if last != len(entries):
            raise ValueError(_UNSEALED)
        self._entries = entries
        self._anchors = anchors
        self._last_anchored = last

    def append(self, kind: str, body: str) -> int:
        """Append a receipt; return its 1-based sequence number."""
        if not isinstance(kind, str) or kind not in _ENTRY_KINDS:
            raise ValueError(f"unknown entry kind: {kind}")
        if not body:
            raise ValueError("entry body must be non-empty")
        if len(self._entries) >= self._max_entries:
            raise ValueError("registry full: budget exceeded")
        seq = len(self._entries) + 1
        entry = LogEntry(seq=seq, kind=kind, body=body)
        if self._state is not None:
            self._state.add_entry(entry)
        self._entries.append(entry)
        return seq

    def has_room(self) -> bool:
        """True while another entry fits within the budget."""
        return len(self._entries) < self._max_entries

    def size(self) -> int:
        """Number of appended entries."""
        return len(self._entries)

    def entry(self, seq: int) -> LogEntry:
        """The entry at seq.

        Raises:
            ValueError: If seq is outside the log.
        """
        if seq < 1 or seq > len(self._entries):
            raise ValueError(f"unknown seq: {seq}")
        return self._entries[seq - 1]

    def root(self) -> str:
        """Hex Merkle root of the log (EMPTY_ROOT when empty)."""
        if not self._entries:
            return EMPTY_ROOT
        leaves = [_leaf_hash(entry) for entry in self._entries]
        return _tree_root(leaves).hex()

    def prove(self, seq: int) -> InclusionProof:
        """Inclusion proof for seq with bottom-up sibling hashes."""
        if seq < 1 or seq > len(self._entries):
            raise ValueError(f"unknown seq: {seq}")
        leaves = [_leaf_hash(entry) for entry in self._entries]
        siblings: list[str] = []
        index = seq - 1
        level = leaves
        while len(level) > 1:
            if len(level) % 2 == 1:
                level = [*level, level[-1]]
            siblings.append(level[index ^ 1].hex())
            level = _parent_level(level)
            index //= 2
        return InclusionProof(
            seq=seq,
            leaves=len(self._entries),
            leaf=leaves[seq - 1].hex(),
            siblings=tuple(siblings),
            root=self.root(),
        )

    def anchor(self, ts: int) -> Anchor:
        """Seal entries past the last anchor with a signed anchor record."""
        if self._keypair is None:
            raise ValueError("registry has no keypair")
        latest = len(self._entries)
        if latest <= self._last_anchored:
            raise ValueError("nothing to anchor")
        unsigned = Anchor(
            v=1,
            anchor_id=f"anch:{latest:06d}",
            seq_from=self._last_anchored + 1,
            seq_to=latest,
            root=self.root(),
            ts=ts,
            signature=b"",
        )
        key = Ed25519PrivateKey.from_private_bytes(self._keypair[0])
        sealed = replace(unsigned, signature=key.sign(unsigned.signable_bytes()))
        if self._state is not None:
            self._state.add_seal(_seal_view(sealed))
        self._anchors.append(sealed)
        self._last_anchored = latest
        return sealed

    def anchors(self) -> tuple[Anchor, ...]:
        """Sealed anchors oldest-first."""
        return tuple(self._anchors)


def _seal_view(anchor: Anchor) -> dict[str, Any]:
    return {**asdict(anchor), "signature": base64.b64encode(anchor.signature).decode()}


def _anchor_of(view: dict[str, Any]) -> Anchor:
    try:
        return Anchor(
            v=view["v"],
            anchor_id=view["anchor_id"],
            seq_from=view["seq_from"],
            seq_to=view["seq_to"],
            root=view["root"],
            ts=view["ts"],
            signature=base64.b64decode(view["signature"], validate=True),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("state: seal does not verify") from exc


def verify_inclusion(proof: InclusionProof, root: str) -> bool:
    """Recompute the root from the proof; exact-match it against root."""
    try:
        if proof.leaves < 1 or proof.seq < 1 or proof.seq > proof.leaves:
            return False
        if _HEX64.fullmatch(proof.leaf) is None:
            return False
        if any(_HEX64.fullmatch(sibling) is None for sibling in proof.siblings):
            return False
        current = bytes.fromhex(proof.leaf)
        siblings = [bytes.fromhex(sibling) for sibling in proof.siblings]
    except (ValueError, TypeError):
        return False
    if len(current) != _DIGEST_LEN:
        return False
    if any(len(sibling) != _DIGEST_LEN for sibling in siblings):
        return False
    index = proof.seq - 1
    for sibling in siblings:
        if index % 2 == 0:
            current = _node_hash(current, sibling)
        else:
            current = _node_hash(sibling, current)
        index //= 2
    return current.hex() == root


def verify_anchor(anchor: Anchor, public_key: bytes) -> bool:
    """Check the anchor's Ed25519 signature; False on any failure."""
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(anchor.signature, anchor.signable_bytes())
    except Exception:
        return False
    return True
