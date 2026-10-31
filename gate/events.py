"""Versioned decision events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from gate.policy import Verdict

if TYPE_CHECKING:
    from gate.shim import Mode


@dataclass(frozen=True)
class DecisionEvent:
    """Versioned decision record; JSON is the console wire format."""

    v: int
    event_id: str
    ts: int
    mode: Mode
    verdict: Verdict
    action_hash: str
    policy_id: str
    cert_jti: str | None
    reason: str
    latency_us: float

    def to_dict(self) -> dict[str, Any]:
        """Wire format; key set frozen by the console contract."""
        return {
            "v": self.v,
            "type": "urn:mandate:decision/v1",
            "event_id": self.event_id,
            "ts": self.ts,
            "mode": self.mode.value,
            "verdict": self.verdict.value,
            "action_hash": self.action_hash,
            "policy_id": self.policy_id,
            "cert_jti": self.cert_jti,
            "reason": self.reason,
            "latency_us": self.latency_us,
        }
