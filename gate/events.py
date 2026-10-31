"""Versioned decision events."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

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

    def to_json(self) -> str:
        """Compact JSON on the pinned console keys (mode/verdict as values)."""
        return json.dumps(
            {
                "v": self.v,
                "id": self.event_id,
                "ts": self.ts,
                "mode": str(self.mode),
                "verdict": str(self.verdict),
                "action": self.action_hash,
                "policy": self.policy_id,
                "cert": self.cert_jti,
                "reason": self.reason,
                "lat_us": self.latency_us,
            },
            separators=(",", ":"),
        )
