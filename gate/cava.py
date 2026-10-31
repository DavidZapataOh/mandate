"""Canonical action objects: fields, bytes, hashing."""

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Freshness:
    """Nonce plus unix-seconds timestamp."""

    nonce: str
    timestamp: int


@dataclass(frozen=True)
class CavaAction:
    """Nine immutable action fields; validated at construction."""

    version: str
    runtime: str
    executable: str
    operation: str
    category: str
    targets: tuple[str, ...]
    reversible: bool
    freshness: Freshness
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.version != "cava/1":
            raise ValueError(f"unsupported version: {self.version!r}")
        if not self.executable:
            raise ValueError("executable must be non-empty")
        if not self.operation:
            raise ValueError("operation must be non-empty")
        if not self.freshness.nonce:
            raise ValueError("freshness nonce must be non-empty")
        if self.freshness.timestamp < 0:
            raise ValueError("freshness timestamp must be >= 0")


def canonical_bytes(action: CavaAction) -> bytes:
    """Canonical JSON over the 9 fields: sort_keys, compact, ASCII."""
    payload = {
        "version": action.version,
        "runtime": action.runtime,
        "executable": action.executable,
        "operation": action.operation,
        "category": action.category,
        "targets": list(action.targets),
        "reversible": action.reversible,
        "freshness": {
            "nonce": action.freshness.nonce,
            "timestamp": action.freshness.timestamp,
        },
        "evidence_refs": list(action.evidence_refs),
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def action_hash(action: CavaAction) -> str:
    """Hex SHA-256 over canonical_bytes."""
    return hashlib.sha256(canonical_bytes(action)).hexdigest()
