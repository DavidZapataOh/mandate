"""Governed run: decide on a raw call, then execute against the bank."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from bank.api import Bank, Payment
from bank.rail import BankRail
from bank.verifier import Freshness as BankFreshness
from bank.verifier import ProposedAction, Verifier
from gate.cava import CavaAction
from gate.consent import Consent, ConsentLedger
from gate.events import DecisionEvent
from gate.policy import Intent, Policy, Rule, Verdict
from gate.shim import Mode, RawCall, canonize, decide


@dataclass(frozen=True)
class RunRequest:
    """Inputs for one governed run.

    Args:
        call: Untrusted raw call to govern.
        policy: Policy to evaluate against.
        intent: Human-stated intent the call must match.
        private_key: Raw Ed25519 private key for certificate issuance.
        mode: Enforcement mode; shadow never issues a certificate.
        now: Current time in unix seconds for execution checks.
        nonce: Unique freshness nonce for this run.
        timestamp: Canonization time in unix seconds.
        scope: Certificate scope string.
        reasoning_commitment: Hex commitment bound into the certificate.
        revocation_index: Revocation bit index bound into the certificate.
        kill_switch: When true, the decision is forced to deny.
        consent: Holder consent presented for consent-required rules.
        holder_keys: Raw Ed25519 public keys trusted to sign consents.
        consents: Ledger of consumed consents; a fresh one when None.
        salt: 32-byte action salt; the gate draws a fresh one when None.
    """

    call: RawCall
    policy: Policy
    intent: Intent
    private_key: bytes
    mode: Mode
    now: int
    nonce: str
    timestamp: int
    scope: str
    reasoning_commitment: str
    revocation_index: int
    kill_switch: bool = False
    consent: Consent | None = None
    holder_keys: tuple[bytes, ...] = ()
    consents: ConsentLedger | None = None
    salt: bytes | None = None


@dataclass(frozen=True)
class RunResult:
    """Outcome of one governed run.

    Args:
        verdict: Policy verdict for the call.
        reason: Machine-readable outcome reason.
        certificate: Issued certificate, or None when denied or shadowed.
        event: Decision event record.
        payment: Recorded payment, or None when nothing executed.
        action: The canonical action the gate decided on.
        salt: Salt of the action hash the gate certified.
    """

    verdict: Verdict
    reason: str
    certificate: str | None
    event: DecisionEvent
    payment: Payment | None
    action: CavaAction | None = None
    salt: bytes | None = field(default=None, repr=False)


def run_governed(request: RunRequest, bank: BankRail, verifier: Verifier) -> RunResult:
    """Decide on the call, then verify and execute the payment when allowed.

    Args:
        request: All inputs for the governed run.
        bank: Rail that moves the money.
        verifier: Certificate verifier bound to the issuer's public key.

    Returns:
        The run result; denied or shadowed runs carry no payment.
    """
    decision = decide(
        request.call,
        request.policy,
        request.intent,
        request.private_key,
        mode=request.mode,
        now=request.now,
        nonce=request.nonce,
        timestamp=request.timestamp,
        scope=request.scope,
        reasoning_commitment=request.reasoning_commitment,
        revocation_index=request.revocation_index,
        kill_switch=request.kill_switch,
        consent=request.consent,
        holder_keys=request.holder_keys,
        consents=request.consents,
        salt=request.salt,
    )
    action = canonize(request.call, request.nonce, request.timestamp)
    if decision.certificate is None:
        return RunResult(
            decision.verdict,
            decision.event.reason,
            None,
            decision.event,
            None,
            action,
            decision.salt,
        )
    bank_result = verifier.verify_and_execute(
        bank, decision.certificate, to_proposed(action), request.now, decision.salt
    )
    return RunResult(
        decision.verdict,
        bank_result.reason,
        decision.certificate,
        decision.event,
        bank_result.payment,
        action,
        decision.salt,
    )


def to_proposed(action: CavaAction) -> ProposedAction:
    """Map a canonical action to the bank's proposed-action shape.

    Args:
        action: The canonized action to map.

    Returns:
        The equivalent proposed action for verification.
    """
    return ProposedAction(
        version=action.version,
        runtime=action.runtime,
        executable=action.executable,
        operation=action.operation,
        category=action.category,
        targets=action.targets,
        reversible=action.reversible,
        freshness=BankFreshness(
            nonce=action.freshness.nonce, timestamp=action.freshness.timestamp
        ),
        evidence_refs=action.evidence_refs,
    )


def load_policy(path: Path) -> Policy:
    """Load a policy from a JSON file.

    Args:
        path: Path to the policy JSON file.

    Returns:
        The parsed policy.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not a valid policy document.
    """
    try:
        raw = json.loads(path.read_text())
        return Policy(
            policy_id=raw["policy_id"],
            version=raw["version"],
            rules=tuple(Rule(**r) for r in raw["rules"]),
        )
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"invalid policy file: {path}") from exc


def build_bank(from_acct: str, to_acct: str, fund_cents: int) -> Bank:
    """Build a bank funded on the source account.

    Args:
        from_acct: Account to fund.
        to_acct: Destination account, opened at zero unless identical.
        fund_cents: Opening balance for the source account in integer cents.

    Returns:
        The funded bank.
    """
    if from_acct == to_acct:
        return Bank({from_acct: fund_cents})
    return Bank({from_acct: fund_cents, to_acct: 0})
