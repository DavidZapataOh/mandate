"""Meta agent: maps an untrusted pay_bill tool call into the gate's RawCall."""

import base64
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from gate.shim import RawCall
from swarm.anchor import ReasoningAnchor, anchor_from
from swarm.meta_client import (
    Item,
    MetaAPIError,
    MetaResponse,
    MetaTrace,
)

MODEL = "muse-spark-1.3"
TOOL_NAME = "pay_bill"

INSTRUCTIONS = (
    "You are a bill-paying assistant acting for the account holder. Read the bill "
    "and pay it by calling pay_bill exactly once, using the payee account, amount "
    "and reference printed on the bill. Amounts are integer cents. If the bill "
    "cannot be paid as printed, explain why and do not call pay_bill."
)

_STRING_FIELDS = ("to_account", "currency", "reference")
_FIELDS = ("to_account", "amount_cents", "currency", "reference")

PAY_BILL_TOOL: Item = {
    "type": "function",
    "name": TOOL_NAME,
    "description": "Pay a bill by transferring money between bank accounts.",
    "parameters": {
        "type": "object",
        "properties": {
            "to_account": {"type": "string"},
            "amount_cents": {"type": "integer"},
            "currency": {"type": "string"},
            "reference": {"type": "string"},
        },
        "required": list(_FIELDS),
        "additionalProperties": False,
    },
}


class ProposalError(ValueError):
    """The model's proposal is not a well-formed pay_bill call."""


def call_from_tool(
    fn_call: Item, source: str, evidence_refs: tuple[str, ...]
) -> RawCall:
    """Map a pay_bill function call to a RawCall without coercing any value.

    Args:
        fn_call: Responses API function_call item.
        source: Debited account, fixed by the human and never by the model.
        evidence_refs: Evidence references to attach to the call.

    Returns:
        The RawCall for the gate.

    Raises:
        ProposalError: On a wrong tool name, malformed JSON, unexpected or
            missing fields, or any field of the wrong type or empty.
    """
    if not isinstance(source, str) or not source:
        raise ProposalError("source must be a non-empty string")
    name = fn_call.get("name")
    if name != TOOL_NAME:
        raise ProposalError(f"unknown tool: {name}")
    try:
        args = json.loads(fn_call.get("arguments", ""))
    except (TypeError, ValueError) as exc:
        raise ProposalError("arguments are not JSON") from exc
    if not isinstance(args, dict):
        raise ProposalError("arguments are not JSON")
    extra = sorted(set(args) - set(_FIELDS))
    if extra:
        raise ProposalError(f"unexpected fields: {', '.join(extra)}")
    missing = [f for f in _FIELDS if f not in args]
    if missing:
        raise ProposalError(f"missing fields: {', '.join(missing)}")
    cents = args["amount_cents"]
    if type(cents) is not int or cents <= 0:
        raise ProposalError("amount_cents must be a positive integer")
    for field in _STRING_FIELDS:
        value = args[field]
        if not isinstance(value, str) or not value:
            raise ProposalError(f"{field} must be a non-empty string")
    return RawCall(
        runtime="muse",
        executable="bank.pay",
        operation="transfer",
        args=(
            ("amount", str(cents)),
            ("currency", args["currency"]),
            ("from", source),
            ("to", args["to_account"]),
            ("ref", args["reference"]),
        ),
        category="payments",
        evidence_refs=evidence_refs,
        reversible=False,
    )


class Responder(Protocol):
    """Anything that can run one Responses API turn (MetaClient)."""

    def respond(
        self,
        model: str,
        input: str | list[Item],  # noqa: A002
        *,
        tools: Iterable[Item] = (),
        instructions: str | None = None,
        effort: str = "medium",
    ) -> MetaResponse: ...


@dataclass(frozen=True)
class Proposal:
    """A model-proposed payment, ready for the gate.

    Args:
        call: The proposed call, mapped for the gate.
        call_id: Id of the function call, needed to report its outcome.
        trace: Audit facts of the Meta call that proposed it.
        anchor: Identity of the Meta response and its encrypted reasoning.
        reasoning_commitment: The anchor digest, committed into the certificate.
        rationale: The model's stated reasoning text.
        transcript: Input and output items, replayable statelessly.
    """

    call: RawCall
    call_id: str
    trace: MetaTrace
    anchor: ReasoningAnchor
    reasoning_commitment: str
    rationale: str
    transcript: tuple[Item, ...]

    def __post_init__(self) -> None:
        if (
            self.reasoning_commitment != self.anchor.digest()
            or self.anchor.model != self.trace.model
            or self.anchor.response_id != self.trace.response_id
        ):
            raise ValueError("proposal: commitment does not match anchor")


def bill_input(pdf: bytes, filename: str, request: str) -> list[Item]:
    """Build the user message carrying the request and the PDF inline."""
    data = base64.b64encode(pdf).decode()
    return [
        {
            "type": "message",
            "role": "user",
            "content": [
                {"type": "input_text", "text": request},
                {
                    "type": "input_file",
                    "filename": filename,
                    "file_data": f"data:application/pdf;base64,{data}",
                },
            ],
        }
    ]


def propose_payment(
    meta: Responder,
    pdf: bytes,
    filename: str,
    request: str,
    *,
    source: str,
    evidence_refs: tuple[str, ...] = (),
    model: str = MODEL,
    effort: str = "low",
) -> Proposal:
    """Ask the model to pay a PDF bill and map its single call for the gate.

    Args:
        meta: Responses API client.
        pdf: Bill bytes, sent inline.
        filename: Bill file name.
        request: User request text.
        source: Debited account, fixed by the human.
        evidence_refs: Evidence references to attach to the call.
        model: Model id.
        effort: Reasoning effort.

    Returns:
        The proposal.

    Raises:
        ProposalError: Unless the model made exactly one well-formed call.
        MetaAPIError: If the call fails or the response cannot be committed to.
    """
    items = bill_input(pdf, filename, request)
    resp = meta.respond(
        model, items, tools=[PAY_BILL_TOOL], instructions=INSTRUCTIONS, effort=effort
    )
    calls = resp.function_calls
    if not calls:
        raise ProposalError("no payment proposed")
    if len(calls) > 1:
        raise ProposalError(f"{len(calls)} payments proposed")
    call = call_from_tool(calls[0], source, evidence_refs)
    try:
        anchor = anchor_from(resp.trace, resp.output)
    except ValueError as exc:
        raise MetaAPIError("response undecodable") from exc
    return Proposal(
        call=call,
        call_id=calls[0]["call_id"],
        trace=resp.trace,
        anchor=anchor,
        reasoning_commitment=anchor.digest(),
        rationale=resp.text,
        transcript=(*items, *resp.output),
    )


def report_outcome(
    meta: Responder,
    proposal: Proposal,
    outcome: dict[str, Any],
    model: str = MODEL,
    effort: str = "low",
) -> MetaResponse:
    """Replay the transcript with the gate's outcome as the tool result."""
    result = {
        "type": "function_call_output",
        "call_id": proposal.call_id,
        "output": json.dumps(outcome, sort_keys=True),
    }
    return meta.respond(
        model,
        [*proposal.transcript, result],
        tools=[PAY_BILL_TOOL],
        instructions=INSTRUCTIONS,
        effort=effort,
    )
