"""Execution shim: intercept, canonize, decide."""

import time
from dataclasses import dataclass
from enum import StrEnum

from gate.cava import CavaAction, Freshness, action_hash
from gate.certs import DEFAULT_TTL_S, CertClaims, issue_certificate
from gate.events import DecisionEvent
from gate.policy import Intent, Policy, Verdict, evaluate

MAPPED_KEYS = ("account", "artifact", "env", "from", "merchant", "ref", "to")


class Mode(StrEnum):
    ENFORCE = "ENFORCE"
    SHADOW = "SHADOW"


@dataclass(frozen=True)
class RawCall:
    """Untrusted agent call; canonize() structures it."""

    runtime: str
    executable: str
    operation: str
    args: tuple[tuple[str, str], ...]
    category: str
    evidence_refs: tuple[str, ...]
    reversible: bool


@dataclass(frozen=True)
class Decision:
    """Outcome of one gated call."""

    verdict: Verdict
    certificate: str | None
    event: DecisionEvent
    shadow_allowed: bool


def canonize(call: RawCall, nonce: str, timestamp: int) -> CavaAction:
    """Map a raw call to CAVA; unknown args ride as sorted k=v extras."""
    args = dict(call.args)
    targets: list[str] = []
    consumed = set(MAPPED_KEYS)
    if "amount" in args and "currency" in args:
        targets.append(f"amount:{args['currency']}:{args['amount']}")
        consumed |= {"amount", "currency"}
    for key in MAPPED_KEYS:
        if key in args:
            targets.append(f"{key}:{args[key]}")
    for key in sorted(args):
        if key not in consumed:
            targets.append(f"{key}={args[key]}")
    return CavaAction(
        version="cava/1",
        runtime=call.runtime,
        executable=call.executable,
        operation=call.operation,
        category=call.category,
        targets=tuple(sorted(targets)),
        reversible=call.reversible,
        freshness=Freshness(nonce=nonce, timestamp=timestamp),
        evidence_refs=call.evidence_refs,
    )


def decide(
    call: RawCall,
    policy: Policy,
    intent: Intent,
    private_key: bytes,
    *,
    mode: Mode,
    now: int,
    nonce: str,
    timestamp: int,
    scope: str,
    reasoning_commitment: str,
    revocation_index: int,
    kill_switch: bool = False,
) -> Decision:
    """Canonize, evaluate, issue-or-deny; shadow never blocks."""
    start = time.perf_counter()
    action = canonize(call, nonce, timestamp)
    digest = action_hash(action)
    verdict: Verdict
    reasons: tuple[str, ...]
    if kill_switch:
        verdict, reasons = Verdict.NOT_MET, ("kill-switch: engaged",)
    else:
        verdict, reasons = evaluate(action, policy, intent)
    certificate = None
    cert_jti = None
    if mode is Mode.ENFORCE and verdict is Verdict.MET:
        claims = CertClaims(
            action_hash=digest,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            verdict=verdict,
            freshness_nonce=nonce,
            issued_at=timestamp,
            expires_at=timestamp + DEFAULT_TTL_S,
            scope=scope,
            reasoning_commitment=reasoning_commitment,
            evidence_refs=action.evidence_refs,
            revocation_index=revocation_index,
        )
        certificate = issue_certificate(claims, private_key, nonce)
        cert_jti = nonce
    latency_us = (time.perf_counter() - start) * 1e6
    event = DecisionEvent(
        v=1,
        event_id=f"evt:{nonce}",
        ts=timestamp,
        mode=mode,
        verdict=verdict,
        action_hash=digest,
        policy_id=policy.policy_id,
        cert_jti=cert_jti,
        reason=reasons[0],
        latency_us=latency_us,
    )
    return Decision(
        verdict=verdict,
        certificate=certificate,
        event=event,
        shadow_allowed=(mode is Mode.SHADOW),
    )
