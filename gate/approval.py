"""Freeze irreversibles for exact-hash human signing."""

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gate.cava import CavaAction, action_hash

FREEZE_TTL_S = 600


@dataclass(frozen=True)
class FreezePayload:
    """Frozen irreversible proposal awaiting a human signature."""

    v: int
    action_hash: str
    summary: tuple[str, ...]
    policy_id: str
    expires_at: int

    def signable_bytes(self) -> bytes:
        """Canonical bytes the human signs (pinned format)."""
        body = json.dumps(
            {
                "action_hash": self.action_hash,
                "summary": list(self.summary),
                "policy_id": self.policy_id,
                "expires_at": self.expires_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return b"freeze/v1:" + body.encode("ascii")

    def to_json(self) -> str:
        """Compact JSON on the pinned widget keys."""
        return json.dumps(
            {
                "v": self.v,
                "action_hash": self.action_hash,
                "summary": list(self.summary),
                "policy_id": self.policy_id,
                "expires_at": self.expires_at,
            },
            separators=(",", ":"),
        )


def summary_for(action: CavaAction) -> tuple[str, str]:
    """Falsifiable human lines derived from the action alone."""
    found: dict[str, str] = {}
    for target in action.targets:
        for key in ("amount", "to", "ref"):
            if target == key or target.startswith(key + ":"):
                found.setdefault(key, target)
    for key in ("amount", "to", "ref"):
        if key not in found:
            raise ValueError(f"cannot summarize: {key} unstated")
    _, ccy, cents_raw = found["amount"].split(":", 2)
    cents = int(cents_raw)
    to = found["to"].split(":", 1)[1]
    ref = found["ref"].split(":", 1)[1]
    line1 = f"Pay {cents // 100}.{cents % 100:02d} {ccy} to {to} (ref {ref})."
    flag = "reversible" if action.reversible else "irreversible"
    line2 = f"Hash {action_hash(action)[:16]} - {action.category} - {flag}."
    return line1, line2


def freeze_proposal(
    action: CavaAction,
    policy_id: str,
    now: int,
    ttl_s: int = FREEZE_TTL_S,
) -> FreezePayload:
    """Freeze an action for human signature."""
    return FreezePayload(
        v=1,
        action_hash=action_hash(action),
        summary=summary_for(action),
        policy_id=policy_id,
        expires_at=now + ttl_s,
    )


def verify_approval(
    public_key: bytes,
    payload: FreezePayload,
    signature: bytes,
    action: CavaAction,
    now: int,
) -> tuple[bool, str]:
    """Expiry, signature, then hash compare; mismatch denies."""
    if now > payload.expires_at:
        return False, "expired: freeze window passed"
    key = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        key.verify(signature, payload.signable_bytes())
    except InvalidSignature:
        return False, "bad-signature: human signature invalid"
    if action_hash(action) != payload.action_hash:
        return False, "mismatch: action hash differs"
    return True, "ok: approved"
