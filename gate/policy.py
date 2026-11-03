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


_MONEY_FIELDS = (
    ("amount", "amount"),
    ("from", "source"),
    ("to", "recipient"),
    ("ref", "reference"),
)


def _money_fields(targets: tuple[str, ...]) -> dict[str, list[str]]:
    """One pass over targets; values of each money field, in order."""
    amount: list[str] = []
    source: list[str] = []
    to: list[str] = []
    ref: list[str] = []
    for target in targets:
        if target.startswith("amount:"):
            amount.append(target[7:])
        elif target.startswith("from:"):
            source.append(target[5:])
        elif target.startswith("to:"):
            to.append(target[3:])
        elif target.startswith("ref:"):
            ref.append(target[4:])
    return {"amount": amount, "from": source, "to": to, "ref": ref}


def _parse_amount(value: str) -> tuple[str, int] | None:
    currency, sep, cents = value.partition(":")
    if not sep or not currency or not cents.isdigit():
        return None
    return (currency, int(cents))


def _check_money(
    fields: dict[str, list[str]], rule: Rule, intent: Intent
) -> tuple[Verdict, tuple[str, ...]] | None:
    """Money checks; any duplicated field is ambiguous because an executor
    could read a different copy than the one checked here."""
    if not fields["amount"]:
        return (Verdict.NOT_CHECKABLE, ("amount not stated",))
    for key, name in _MONEY_FIELDS:
        if len(fields[key]) > 1:
            return (Verdict.NOT_CHECKABLE, (f"{name} target ambiguous",))
    parsed = _parse_amount(fields["amount"][0])
    if parsed is None:
        return (Verdict.NOT_CHECKABLE, ("amount target malformed",))
    currency, cents = parsed
    if currency != intent.currency:
        return (Verdict.NOT_MET, ("currency mismatch",))
    if rule.amount_exact and cents != intent.amount_cents:
        return (Verdict.NOT_MET, ("amount differs from intent",))
    if rule.amount_lte_cents is not None and cents > rule.amount_lte_cents:
        return (Verdict.NOT_MET, ("amount exceeds ceiling",))
    for key, expected, name in (
        ("to", intent.recipient, "recipient"),
        ("ref", intent.reference, "reference"),
    ):
        if not fields[key]:
            return (Verdict.NOT_CHECKABLE, (f"{name} not stated",))
        if fields[key][0] != expected:
            return (Verdict.NOT_MET, (f"{name} differs from intent",))
    return None


def evaluate(
    action: CavaAction, policy: Policy, intent: Intent
) -> tuple[Verdict, tuple[str, ...]]:
    """Verdict plus exact forensic reasons; never guesses."""
    rule = matched_rule(action, policy)
    if rule is None:
        return (Verdict.NOT_MET, ("no rule matches",))
    if rule.amount_exact or rule.amount_lte_cents is not None:
        failed = _check_money(_money_fields(action.targets), rule, intent)
        if failed is not None:
            return failed
    return (Verdict.MET, (f"rule {rule.rule_id} satisfied",))
