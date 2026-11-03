"""Per-decision attribution of the Meta call behind a gate event."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gate.events import DecisionEvent
    from swarm.attacker import AttackerTrace
    from swarm.hookio import ToolCall
    from swarm.meta_client import MetaTrace

PROVIDER_META_API = "meta-model-api"
PROVIDER_MUSE_CODE = "muse-code"


@dataclass(frozen=True)
class Attribution:
    """The model call that produced a decision.

    Args:
        provider: One of meta-model-api, muse-code, baseten, meta-fallback.
        model: Model id.
        response_id: Provider response id, when one exists.
        request_id: Provider request id, when one exists.
        latency_ms: Wall time of the call.
        input_tokens: Billed input tokens.
        output_tokens: Billed output tokens.
        anchor: Anchored evidence digest, when one exists.
    """

    provider: str
    model: str
    response_id: str | None
    request_id: str | None
    latency_ms: float | None
    input_tokens: int | None
    output_tokens: int | None
    anchor: str | None


def from_trace(trace: MetaTrace, anchor: str | None) -> Attribution:
    """Attribute a decision to a Meta Model API call."""
    return Attribution(
        provider=PROVIDER_META_API,
        model=trace.model,
        response_id=trace.response_id,
        request_id=trace.request_id,
        latency_ms=trace.latency_ms,
        input_tokens=trace.input_tokens,
        output_tokens=trace.output_tokens,
        anchor=anchor,
    )


def from_attacker(trace: AttackerTrace) -> Attribution:
    """Attribute an attack to the provider that actually served it."""
    return Attribution(
        provider=trace.provider,
        model=trace.model,
        response_id=None,
        request_id=trace.request_id,
        latency_ms=trace.latency_ms,
        input_tokens=None,
        output_tokens=None,
        anchor=None,
    )


def from_hook(call: ToolCall) -> Attribution:
    """Attribute a Muse Code tool decision; hooks see no response id.

    For provider muse-code, ``request_id`` carries the Muse Code tool_use_id,
    since no provider request id exists for hook decisions.
    """
    return Attribution(
        provider=PROVIDER_MUSE_CODE,
        model=call.model,
        response_id=None,
        request_id=call.tool_use_id,
        latency_ms=None,
        input_tokens=None,
        output_tokens=None,
        anchor=None,
    )


def event_v2_json(event: DecisionEvent, attribution: Attribution | None) -> str:
    """Wrap the v1 event JSON untouched with its attribution (or null)."""
    return json.dumps(
        {
            "v": 2,
            "event": json.loads(event.to_json()),
            "meta": None if attribution is None else asdict(attribution),
        },
        separators=(",", ":"),
    )


def read_event_line(line: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Parse a v2 or bare v1 event object into (event, meta).

    Raises:
        ValueError: If the line is neither shape.
    """
    obj = json.loads(line)
    if isinstance(obj, dict):
        v = obj.get("v")
        if type(v) is int and v == 2:
            meta = obj.get("meta")
            if isinstance(obj.get("event"), dict) and (
                meta is None or isinstance(meta, dict)
            ):
                return obj["event"], meta
        elif type(v) is int and v == 1:
            return obj, None
    raise ValueError("unknown event line")
