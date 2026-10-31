"""Deterministic declarative policy engine."""

from dataclasses import dataclass
from enum import StrEnum

from gate.cava import CavaAction


class Verdict(StrEnum):
    MET = "MET"
    NOT_MET = "NOT_MET"
    NOT_CHECKABLE = "NOT_CHECKABLE"


@dataclass(frozen=True)
class Intent:
    """Human-stated instruction: exact money, payee, reference."""

    amount_cents: int
    currency: str
    recipient: str
    reference: str


@dataclass(frozen=True)
class Rule:
    """One declarative rule; first match in policy order decides."""

    rule_id: str
    actor: str
    operation: str
    target: str
    amount_exact: bool
    amount_lte_cents: int | None
    approval_required: bool


@dataclass(frozen=True)
class Policy:
    """Named versioned rule list."""

    policy_id: str
    version: int
    rules: tuple[Rule, ...]


def matched_rule(action: CavaAction, policy: Policy) -> Rule | None:
    """First rule matching actor, operation, and target ("*" matches all)."""
    actor = f"{action.runtime}:{action.executable}"
    for rule in policy.rules:
        if rule.actor != "*" and rule.actor != actor:
            continue
        if rule.operation != "*" and rule.operation != action.operation:
            continue
        if rule.target != "*" and rule.target not in action.targets:
            continue
        return rule
    return None


def _parse_amount(targets: tuple[str, ...]) -> tuple[str, int] | None:
    for target in targets:
        if target.startswith("amount:"):
            parts = target.split(":")
            if len(parts) != 3 or not parts[1] or not parts[2].isdigit():
                return None
            return (parts[1], int(parts[2]))
    return None


def evaluate(
    action: CavaAction, policy: Policy, intent: Intent
) -> tuple[Verdict, tuple[str, ...]]:
    """Verdict plus exact forensic reasons; never guesses."""
    rule = matched_rule(action, policy)
    if rule is None:
        return (Verdict.NOT_MET, ("no rule matches",))
    if rule.amount_exact or rule.amount_lte_cents is not None:
        found = any(t.startswith("amount:") for t in action.targets)
        if not found:
            return (Verdict.NOT_CHECKABLE, ("amount not stated",))
        parsed = _parse_amount(action.targets)
        if parsed is None:
            return (Verdict.NOT_CHECKABLE, ("amount target malformed",))
        currency, cents = parsed
        if currency != intent.currency:
            return (Verdict.NOT_MET, ("currency mismatch",))
        if rule.amount_exact and cents != intent.amount_cents:
            return (Verdict.NOT_MET, ("amount differs from intent",))
        if rule.amount_lte_cents is not None and cents > rule.amount_lte_cents:
            return (Verdict.NOT_MET, ("amount exceeds ceiling",))
    return (Verdict.MET, (f"rule {rule.rule_id} satisfied",))
