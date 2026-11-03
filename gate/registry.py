"""Append-only Merkle receipt log with inclusion proofs."""

import hashlib
import json
import re
from dataclasses import dataclass, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

EMPTY_ROOT = hashlib.sha256(b"registry/v1:empty").hexdigest()

_LEAF_PREFIX = b"leaf/v1:"
_NODE_PREFIX = b"node/v1:"
_ANCHOR_PREFIX = b"anchor/v1:"
_ENTRY_KINDS = frozenset({"execution", "denial", "anchor"})
_DIGEST_LEN = 32
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")


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
    ) -> None:
        """Create an empty registry capped at max_entries entries."""
        self._max_entries = max_entries
        self._keypair = keypair
        self._entries: list[LogEntry] = []
        self._anchors: list[Anchor] = []
        self._last_anchored = 0

    def append(self, kind: str, body: str) -> int:
        """Append a receipt; return its 1-based sequence number."""
        if not isinstance(kind, str) or kind not in _ENTRY_KINDS:
            raise ValueError(f"unknown entry kind: {kind}")
        if not body:
            raise ValueError("entry body must be non-empty")
        if len(self._entries) >= self._max_entries:
            raise ValueError("registry full: budget exceeded")
        seq = len(self._entries) + 1
        self._entries.append(LogEntry(seq=seq, kind=kind, body=body))
        return seq

    def has_room(self) -> bool:
        """True while another entry fits within the budget."""
        return len(self._entries) < self._max_entries

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
        self._anchors.append(sealed)
        self._last_anchored = latest
        return sealed

    def anchors(self) -> tuple[Anchor, ...]:
        """Sealed anchors oldest-first."""
        return tuple(self._anchors)


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
