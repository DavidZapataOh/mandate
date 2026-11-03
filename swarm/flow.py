"""Governed bill run: model proposal, gate decision, bank execution, replay."""

from dataclasses import dataclass

from bank.api import Bank
from bank.verifier import Verifier
from gate.policy import Intent, Policy, Rule
from gate.shim import Mode
from mandate.client import RunRequest, RunResult, run_governed
from swarm.agent import Proposal, Responder, propose_payment, report_outcome
from swarm.attribution import Attribution, from_trace
from swarm.meta_client import MetaAPIError

PAYMENTS_POLICY = Policy(
    policy_id="payments",
    version=1,
    rules=(
        Rule(
            rule_id="pay-intent",
            actor="muse:bank.pay",
            operation="transfer",
            target="*",
            amount_exact=True,
            amount_lte_cents=None,
            approval_required=False,
        ),
    ),
)


@dataclass(frozen=True)
class BillRun:
    """One governed bill run.

    Args:
        proposal: The model's proposed payment.
        result: The gate and bank outcome.
        confirmation: The model's reply after seeing the outcome, or None if
            reporting failed.
        report_error: Why reporting failed, or None.
        attribution: The Meta call behind the proposal, with its anchor.
    """

    proposal: Proposal
    result: RunResult
    confirmation: str | None
    report_error: str | None
    attribution: Attribution


def run_bill(
    meta: Responder,
    pdf: bytes,
    filename: str,
    request: str,
    intent: Intent,
    policy: Policy,
    gate_key: bytes,
    bank: Bank,
    verifier: Verifier,
    now: int,
    nonce: str,
    revocation_index: int,
    *,
    source: str,
) -> BillRun:
    """Propose a payment from a bill, govern it, execute it, and report back.

    Args:
        meta: Responses API client.
        pdf: Bill bytes.
        filename: Bill file name.
        request: User request text.
        intent: Human-stated intent the proposal must match.
        policy: Policy to evaluate against.
        gate_key: Raw Ed25519 private key for certificate issuance.
        bank: Ledger to execute against.
        verifier: Certificate verifier bound to the issuer's public key.
        now: Current time in unix seconds.
        nonce: Unique freshness nonce for this run.
        revocation_index: Revocation bit index bound into the certificate.
        source: Debited account, fixed by the human and not by the model.

    Returns:
        The proposal, the governed result, and the model's confirmation or
        the error that prevented it. A failed report never discards the result.

    Raises:
        ProposalError: If the model's proposal is not one well-formed call;
            nothing reaches the gate.
        MetaAPIError: If the proposal call fails; nothing executes.
    """
    proposal = propose_payment(meta, pdf, filename, request, source=source)
    result = run_governed(
        RunRequest(
            call=proposal.call,
            policy=policy,
            intent=intent,
            private_key=gate_key,
            mode=Mode.ENFORCE,
            now=now,
            nonce=nonce,
            timestamp=now,
            scope=f"muse:bank.pay:transfer:{source}",
            reasoning_commitment=proposal.reasoning_commitment,
            revocation_index=revocation_index,
        ),
        bank,
        verifier,
    )
    outcome = {
        "status": "denied" if result.payment is None else "executed",
        "reason": result.reason,
        "payment": None if result.payment is None else result.payment.payment_id,
    }
    attribution = from_trace(proposal.trace, proposal.anchor.digest())
    try:
        resp = report_outcome(meta, proposal, outcome)
    except MetaAPIError as exc:
        return BillRun(proposal, result, None, str(exc), attribution)
    return BillRun(proposal, result, resp.text, None, attribution)
