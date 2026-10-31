"""MCP proxy: server-routed allow-list checks with decision events."""

import time
from dataclasses import dataclass

from gate.cava import action_hash
from gate.events import DecisionEvent
from gate.policy import Verdict
from gate.shim import Mode, RawCall, canonize


@dataclass(frozen=True)
class ToolGrant:
    """One declared tool with its allowed scopes."""

    tool: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class Manifest:
    """Frozen allow-list for one MCP server."""

    v: int
    server: str
    grants: tuple[ToolGrant, ...]


@dataclass(frozen=True)
class ProxyCall:
    """One inbound MCP call, server id from the connection."""

    server: str
    tool: str
    scope: str


@dataclass(frozen=True)
class ProxyResult:
    """Allow/deny plus its forensic event."""

    allowed: bool
    reason: str
    event: DecisionEvent


def check(manifest: Manifest, tool: str, scope: str) -> tuple[bool, str]:
    """Tool then scope against one manifest."""
    for grant in manifest.grants:
        if grant.tool == tool:
            if scope in grant.scopes:
                return (True, "ok: declared")
            return (False, "denied: scope exceeds grant")
    return (False, "denied: tool undeclared")


def proxy_call(
    manifests: tuple[Manifest, ...],
    call: ProxyCall,
    nonce: str,
    timestamp: int,
) -> ProxyResult:
    """Route by server id; allow or deny with a decision event."""
    start = time.perf_counter()
    manifest = next((m for m in manifests if m.server == call.server), None)
    if manifest is None:
        allowed, reason = False, "denied: server undeclared"
    else:
        allowed, reason = check(manifest, call.tool, call.scope)
    latency_us = (time.perf_counter() - start) * 1e6
    action = canonize(
        RawCall(
            runtime="mcp",
            executable=f"mcp:{call.server}",
            operation=call.tool,
            args=(("scope", call.scope),),
            category="mcp",
            evidence_refs=(),
            reversible=True,
        ),
        nonce,
        timestamp,
    )
    event = DecisionEvent(
        v=1,
        event_id=f"evt:{nonce}",
        ts=timestamp,
        mode=Mode.ENFORCE,
        verdict=Verdict.MET if allowed else Verdict.NOT_MET,
        action_hash=action_hash(action),
        policy_id=f"manifest:{call.server}",
        cert_jti=None,
        reason=reason,
        latency_us=latency_us,
    )
    return ProxyResult(allowed=allowed, reason=reason, event=event)
