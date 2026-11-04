"""Console lines: one wire shape for every event the live feed carries.

Every string in a line is data. Python stores it verbatim, with no HTML
escaping; the console renders it as text and never as markup.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, cast

from bank.rail import bank_view
from gate.cava import CavaAction, action_commitment, action_hash, canonical_bytes
from gate.certs import read_claims
from gate.policy import matched_rule
from swarm.attribution import from_attacker
from swarm.nimbus import AGENT, SUMMARIES, StepOutcome

if TYPE_CHECKING:
    from bank.api import Payment
    from gate.consent import Consent
    from gate.events import DecisionEvent
    from gate.policy import Policy
    from gate.registry import InclusionProof
    from swarm.attacker import AttackerTrace
    from swarm.flow import BillRun
    from swarm.redteam import AttackOutcome, AttackPlan

SOURCES = ("desk", "attack", "hook", "bill", "deploy")

_LINE_KEYS = ("v", "seq", "source", "event", "meta", "subject", "forensic")
_EVENT_KEYS = frozenset(
    ("v", "id", "ts", "mode", "verdict", "action", "policy", "cert", "reason", "lat_us")
)
_FORENSIC_KEYS = frozenset(
    (
        "cava",
        "action_hash",
        "policy",
        "cert_claims",
        "consent",
        "registry",
        "anchor",
        "bank",
    )
)
_SUBJECT_KEYS = {
    "desk": frozenset(
        ("step", "quote_id", "status", "summary", "payment_id", "reason")
    ),
    "attack": frozenset(
        (
            "attack",
            "layer",
            "reason",
            "blocked",
            "moved_cents",
            "narrative",
            "origin",
        )
    ),
    "hook": frozenset(("agent", "tool", "targets", "tool_use_id")),
    "bill": frozenset(("proposal_call_id", "summary", "confirmation", "report_error")),
    "deploy": frozenset(("step", "agent", "summary", "layer", "reason", "blocked")),
}
_DESK_STEPS = ("intent", "quote", "approve", "confirm")
_RECORD_KEYS = frozenset(("agent", "tool", "targets", "event", "tool_use_id"))
_MALFORMED = "console line: malformed"
_SAFE_INT = 2**53 - 1
_CONSENT_FIELDS = (
    "amount_cents",
    "currency",
    "recipient",
    "reference",
    "source",
    "nonce",
    "expires_at",
)
_BANK_KEYS = frozenset(("rail", "provider", "transfer_id", "status", "idempotency_key"))
_RAILS = ("simulated", "sandbox")
_Check = Callable[[object], bool]


@dataclass(frozen=True)
class ConsoleLine:
    """One event of the live feed.

    Args:
        seq: Publication number, at least 1; 0 until published.
        source: One of ``SOURCES``: desk, attack, hook, bill or deploy.
        event: Gate decision event object, or None when the gate did not decide.
        meta: Attribution object of the model call, or None.
        subject: Source-specific facts.
        forensic: Evidence behind the decision, or None.
    """

    seq: int
    source: str
    event: dict[str, Any] | None
    meta: dict[str, Any] | None
    subject: dict[str, Any]
    forensic: dict[str, Any] | None


def console_line_json(line: ConsoleLine) -> str:
    """Serialize a line to its compact v3 wire form."""
    return json.dumps(
        {
            "v": 3,
            "seq": line.seq,
            "source": line.source,
            "event": line.event,
            "meta": line.meta,
            "subject": line.subject,
            "forensic": line.forensic,
        },
        separators=(",", ":"),
        allow_nan=False,
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# The browser parses numbers as doubles, so these mirror its checks exactly.
def _safe_int(value: object) -> bool:
    return _is_int(value) and abs(cast("int", value)) <= _SAFE_INT


def _finite(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int | float)
        and math.isfinite(value)
    )


def _nullable(check: _Check) -> _Check:
    return lambda value: value is None or check(value)


def _is_str(value: object) -> bool:
    return isinstance(value, str)


_EVENT_CHECKS: dict[str, _Check] = {
    "id": _is_str,
    "ts": _safe_int,
    "mode": _is_str,
    "verdict": _is_str,
    "action": _is_str,
    "policy": _is_str,
    "cert": _nullable(_is_str),
    "reason": _is_str,
    "lat_us": _finite,
}
_META_CHECKS: dict[str, _Check] = {
    "provider": _is_str,
    "model": _is_str,
    "response_id": _nullable(_is_str),
    "request_id": _nullable(_is_str),
    "latency_ms": _nullable(_finite),
    "input_tokens": _nullable(_safe_int),
    "output_tokens": _nullable(_safe_int),
    "anchor": _nullable(_is_str),
}


def _event_ok(event: object) -> bool:
    return (
        isinstance(event, dict)
        and event.keys() == _EVENT_KEYS
        and _is_int(event["v"])
        and event["v"] == 1
        and all(check(event[key]) for key, check in _EVENT_CHECKS.items())
    )


def _meta_ok(meta: object) -> bool:
    return meta is None or (
        isinstance(meta, dict)
        and meta.keys() == _META_CHECKS.keys()
        and all(check(meta[key]) for key, check in _META_CHECKS.items())
    )


def _bank_ok(bank: object) -> bool:
    return bank is None or (
        isinstance(bank, dict)
        and bank.keys() == _BANK_KEYS
        and bank["rail"] in _RAILS
        and _is_str(bank["transfer_id"])
        and _is_str(bank["status"])
        and _nullable(_is_str)(bank["provider"])
        and _nullable(_is_str)(bank["idempotency_key"])
    )


def _forensic_ok(forensic: object) -> bool:
    return forensic is None or (
        isinstance(forensic, dict)
        and forensic.keys() == _FORENSIC_KEYS
        and _bank_ok(forensic["bank"])
    )


def _loads(text: str) -> Any:
    def refuse(name: str) -> None:
        raise ValueError(name)

    try:
        return json.loads(text, parse_constant=refuse)
    except (ValueError, RecursionError) as exc:
        raise ValueError("console line: not JSON") from exc


def hook_line(record: dict[str, Any]) -> ConsoleLine:
    """Lift a Muse Code journal record to a console line.

    Args:
        record: Journal record with ``agent``, ``tool``, ``targets``, ``event``
            and optionally ``tool_use_id``; ``event`` is a v1 object or a v2
            wrapper.

    Returns:
        An unpublished (seq 0) hook line without forensic evidence.

    Raises:
        ValueError: If the record has any other shape.
    """
    keys = record.keys()
    targets = record.get("targets")
    tool_use_id = record.get("tool_use_id")
    if (
        not {"agent", "tool", "targets", "event"} <= keys
        or not keys <= _RECORD_KEYS
        or not isinstance(record["agent"], str)
        or not isinstance(record["tool"], str)
        or not isinstance(targets, list)
        or not all(isinstance(t, str) for t in targets)
        or not (tool_use_id is None or isinstance(tool_use_id, str))
    ):
        raise ValueError(_MALFORMED)
    event, meta = record["event"], None
    if isinstance(event, dict) and event.get("v") == 2 and _is_int(event.get("v")):
        wrapper = event
        if wrapper.keys() != {"v", "event", "meta"}:
            raise ValueError(_MALFORMED)
        event, meta = wrapper["event"], wrapper["meta"]
    if not _event_ok(event) or not _meta_ok(meta):
        raise ValueError(_MALFORMED)
    subject = {
        "agent": record["agent"],
        "tool": record["tool"],
        "targets": targets,
        "tool_use_id": tool_use_id,
    }
    return ConsoleLine(0, "hook", event, meta, subject, None)


def _v3_line(obj: dict[str, Any]) -> ConsoleLine:
    seq, source, subject = obj["seq"], obj["source"], obj["subject"]
    forensic = obj["forensic"]
    if (
        tuple(obj) != _LINE_KEYS
        or not _is_int(seq)
        or seq < 1
        or source not in SOURCES
        or not isinstance(subject, dict)
        or subject.keys() != _SUBJECT_KEYS[source]
        or not (obj["event"] is None or _event_ok(obj["event"]))
        or not _meta_ok(obj["meta"])
        or not _forensic_ok(forensic)
    ):
        raise ValueError(_MALFORMED)
    return ConsoleLine(seq, source, obj["event"], obj["meta"], subject, forensic)


def read_console_line(text: str) -> ConsoleLine:
    """Read a v3 line or a Muse Code journal record.

    Args:
        text: One JSON document.

    Returns:
        The line; journal records come back unpublished with seq 0.

    Raises:
        ValueError: ``console line: not JSON`` (including NaN, Infinity and
            nesting too deep to decode), ``console line: malformed`` for a v3
            or journal shape with bad content, or ``console line: unknown
            shape`` for anything else.
    """
    obj = _loads(text)
    if isinstance(obj, dict):
        v = obj.get("v")
        if _is_int(v) and v == 3:
            return _v3_line(obj)
        if "v" not in obj and "agent" in obj:
            return hook_line(obj)
    raise ValueError("console line: unknown shape")


def read_hook_record(text: str) -> ConsoleLine:
    """Read one Muse Code journal record, and nothing else.

    The journal only ever holds hook records, so a v3 line found there is
    refused rather than republished under the source it claims.

    Args:
        text: One JSON document.

    Returns:
        The unpublished (seq 0) hook line.

    Raises:
        ValueError: If the text is not a journal record the console can parse.
    """
    obj = _loads(text)
    if not isinstance(obj, dict) or "v" in obj:
        raise ValueError("console line: unknown shape")
    return hook_line(obj)


def forensic_of(
    action: CavaAction,
    policy: Policy,
    certificate: str | None,
    gate_pub: bytes,
    consent: Consent | None = None,
    proof: InclusionProof | None = None,
    anchor: str | None = None,
    *,
    salt: bytes | None,
    payment: Payment | None = None,
) -> dict[str, Any]:
    """Build the forensic block for one decided action.

    Args:
        action: The canonical action the gate decided on.
        policy: Policy the action was evaluated against.
        certificate: Issued certificate, or None.
        gate_pub: Gate public key; claims are shown only if its signature holds.
        consent: Holder consent presented, or None.
        proof: Registry inclusion proof for the certificate, or None.
        anchor: Anchored evidence digest, or None.
        salt: Salt of the gate's action hash; None for a layer that hashes
            the action unsalted (the MCP proxy).
        payment: Payment the rail executed for the action, or None.

    Returns:
        The forensic object in wire key order.
    """
    rule = matched_rule(action, policy)
    claims = None if certificate is None else read_claims(certificate, gate_pub)[0]
    return {
        "cava": json.loads(canonical_bytes(action)),
        "action_hash": (
            action_hash(action) if salt is None else action_commitment(action, salt)
        ),
        "policy": {
            "policy_id": policy.policy_id,
            "rule_id": None if rule is None else rule.rule_id,
        },
        "cert_claims": claims,
        "consent": None if consent is None else _consent_fields(consent),
        "registry": None if proof is None else _registry_fields(proof),
        "anchor": anchor,
        "bank": bank_view(payment),
    }


def _consent_fields(consent: Consent) -> dict[str, Any]:
    # Signed fields only: the one-time key and its certificate stay off the wire.
    return {name: getattr(consent, name) for name in _CONSENT_FIELDS}


def _registry_fields(proof: InclusionProof) -> dict[str, Any]:
    return {
        "seq": proof.seq,
        "root": proof.root,
        "leaves": proof.leaves,
        "leaf": proof.leaf,
        "siblings": list(proof.siblings),
    }


def pay_summary(
    amount: str, currency: str, recipient: str, reference: str, source: str
) -> str:
    """One-line description of a payment.

    Args:
        amount: Integer cents as ASCII digits; any other text is shown as is.
        currency: Currency code.
        recipient: Payee account.
        reference: Payment reference.
        source: Debit account.

    Returns:
        The sentence shown for the payment.
    """
    if amount.isascii() and amount.isdigit():
        cents = int(amount)
        shown = f"{cents // 100}.{cents % 100:02d}"
    else:
        shown = amount
    return f"Pay {shown} {currency} to {recipient} (ref {reference}) from {source}"


def desk_line(
    step: str,
    view: dict[str, Any],
    summary: str,
    event: DecisionEvent | None = None,
    forensic: dict[str, Any] | None = None,
) -> ConsoleLine:
    """Build the line for one desk step.

    Args:
        step: ``intent``, ``quote``, ``approve`` or ``confirm``.
        view: The desk's view of the step (``status``, optional ids and reason).
        summary: Payment sentence.
        event: Gate decision event, when the gate decided.
        forensic: Forensic block, when there is one.

    Returns:
        An unpublished desk line.

    Raises:
        ValueError: If the step is unknown.
    """
    if step not in _DESK_STEPS:
        raise ValueError(f"unknown desk step: {step}")
    subject = {
        "step": step,
        "quote_id": view.get("quote_id"),
        "status": view["status"],
        "summary": summary,
        "payment_id": view.get("payment_id"),
        "reason": view.get("reason"),
    }
    decided = None if event is None else json.loads(event.to_json())
    return ConsoleLine(0, "desk", decided, None, subject, forensic)


def bill_line(run: BillRun, policy: Policy, gate_pub: bytes) -> ConsoleLine:
    """Build the line for one governed bill run.

    Args:
        run: The completed bill run.
        policy: Policy the run was evaluated against.
        gate_pub: Gate public key for reading the certificate claims.

    Returns:
        An unpublished bill line carrying the run's forensic block.
    """
    args = dict(run.proposal.call.args)
    summary = pay_summary(
        args.get("amount", ""),
        args.get("currency", ""),
        args.get("to", ""),
        args.get("ref", ""),
        args.get("from", ""),
    )
    result = run.result
    forensic = (
        None
        if result.action is None
        else forensic_of(
            result.action,
            policy,
            result.certificate,
            gate_pub,
            anchor=run.attribution.anchor,
            salt=result.salt,
            payment=result.payment,
        )
    )
    subject = {
        "proposal_call_id": run.proposal.call_id,
        "summary": summary,
        "confirmation": run.confirmation,
        "report_error": run.report_error,
    }
    return ConsoleLine(
        0,
        "bill",
        json.loads(result.event.to_json()),
        asdict(run.attribution),
        subject,
        forensic,
    )


def attack_line(
    plan: AttackPlan,
    outcome: AttackOutcome,
    trace: AttackerTrace | None,
    origin: str,
    gate_pub: bytes,
) -> ConsoleLine:
    """Build the line for one applied attack.

    Args:
        plan: The attack plan that was applied.
        outcome: What the defense layers did with it.
        trace: The attacker model call behind the plan, or None for a template.
        origin: ``template`` (no trace) or ``model`` (with a trace).
        gate_pub: Gate public key for reading the certificate claims.

    Returns:
        An unpublished attack line.

    Raises:
        ValueError: If the origin does not match the trace.
    """
    if (origin, trace is None) not in (("template", True), ("model", False)):
        raise ValueError("attack origin does not match its trace")
    forensic = (
        None
        if outcome.action is None
        else forensic_of(
            outcome.action,
            outcome.policy,
            outcome.certificate,
            gate_pub,
            consent=outcome.consent,
            salt=outcome.salt,
            payment=outcome.payment,
        )
    )
    subject = {
        "attack": str(outcome.kind),
        "layer": outcome.layer,
        "reason": outcome.reason,
        "blocked": outcome.blocked,
        "moved_cents": outcome.moved_cents,
        "narrative": plan.narrative,
        "origin": origin,
    }
    event = None if outcome.event is None else json.loads(outcome.event.to_json())
    meta = None if trace is None else asdict(from_attacker(trace))
    return ConsoleLine(0, "attack", event, meta, subject, forensic)


def campaign_lines(
    steps: list[tuple[AttackPlan, AttackerTrace | None]],
    outcomes: list[AttackOutcome],
    gate_pub: bytes,
) -> list[ConsoleLine]:
    """Build one attack line per campaign step.

    Args:
        steps: Plans with the attacker call that produced each.
        outcomes: Outcomes in the same order as ``steps``.
        gate_pub: Gate public key for reading the certificate claims.

    Returns:
        The lines in step order.

    Raises:
        ValueError: If the two lists differ in length.
    """
    return [
        attack_line(
            plan, outcome, trace, "template" if trace is None else "model", gate_pub
        )
        for (plan, trace), outcome in zip(steps, outcomes, strict=True)
    ]


def deploy_line(outcome: StepOutcome, gate_pub: bytes) -> ConsoleLine:
    """Build the line for one Nimbus deploy step.

    Args:
        outcome: What the step did and which layer decided it.
        gate_pub: Gate public key for reading the certificate claims.

    Returns:
        An unpublished deploy line.
    """
    subject = {
        "step": str(outcome.step),
        "agent": AGENT,
        "summary": SUMMARIES[outcome.step],
        "layer": outcome.layer,
        "reason": outcome.reason,
        "blocked": outcome.blocked,
    }
    forensic = forensic_of(
        outcome.action,
        outcome.policy,
        outcome.certificate,
        gate_pub,
        salt=outcome.salt,
    )
    event = json.loads(outcome.event.to_json())
    return ConsoleLine(0, "deploy", event, None, subject, forensic)
