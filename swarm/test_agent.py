import base64
import dataclasses
import json

import pytest

from swarm.agent import (
    INSTRUCTIONS,
    PAY_BILL_TOOL,
    ProposalError,
    bill_input,
    call_from_tool,
    propose_payment,
    report_outcome,
)
from swarm.anchor import ReasoningAnchor
from swarm.conftest import ARGS, REASONING, TRACE, message, tool_call
from swarm.meta_client import MetaAPIError

ANCHOR_1 = "ecdf64cc119eedfb70667704cdb4f24c8c26cdfee47d2f628fd095dc2ab139f6"


def test_call_from_tool_maps_to_raw_call():
    call = call_from_tool(tool_call(), "checking-881", evidence_refs=("ev:1",))
    assert (call.runtime, call.executable, call.operation) == (
        "muse",
        "bank.pay",
        "transfer",
    )
    assert (call.category, call.reversible) == ("payments", False)
    assert call.evidence_refs == ("ev:1",)
    assert call.args == (
        ("amount", "20000"),
        ("currency", "USD"),
        ("from", "checking-881"),
        ("to", "acme-991"),
        ("ref", "A-991"),
    )


@pytest.mark.parametrize(
    ("args", "match"),
    [
        ("{not json", "arguments are not JSON"),
        ("[1, 2]", "arguments are not JSON"),
        (dict(ARGS, extra="x"), "unexpected fields: extra"),
        (
            {k: v for k, v in ARGS.items() if k != "reference"},
            "missing fields: reference",
        ),
        (dict(ARGS, amount_cents="20000"), "amount_cents must be a positive integer"),
        (dict(ARGS, amount_cents=0), "amount_cents must be a positive integer"),
        (dict(ARGS, amount_cents=True), "amount_cents must be a positive integer"),
        (dict(ARGS, amount_cents=200.0), "amount_cents must be a positive integer"),
        (dict(ARGS, to_account=""), "to_account must be a non-empty string"),
        (dict(ARGS, currency=840), "currency must be a non-empty string"),
    ],
)
def test_call_from_tool_rejects_bad_arguments(args, match):
    fn = tool_call()
    fn["arguments"] = args if isinstance(args, str) else json.dumps(args)
    with pytest.raises(ProposalError, match=match):
        call_from_tool(fn, "checking-881", evidence_refs=())


def test_call_from_tool_rejects_other_tools():
    with pytest.raises(ProposalError, match="unknown tool: wire_money"):
        call_from_tool(tool_call(name="wire_money"), "checking-881", evidence_refs=())


def test_bill_input_carries_pdf_inline():
    item = bill_input(b"%PDF-1.4 x", "acme.pdf", "Pay this bill.")[0]
    assert (item["type"], item["role"]) == ("message", "user")
    assert item["content"][0] == {"type": "input_text", "text": "Pay this bill."}
    assert item["content"][1] == {
        "type": "input_file",
        "filename": "acme.pdf",
        "file_data": "data:application/pdf;base64,"
        + base64.b64encode(b"%PDF-1.4 x").decode(),
    }


def test_propose_payment_returns_governable_proposal(fake_meta):
    output = [REASONING, message("Paying Acme."), tool_call()]
    meta = fake_meta(output)
    proposal = propose_payment(
        meta, b"%PDF", "acme.pdf", "Pay this bill.", source="checking-881"
    )
    sent = meta.requests[0]
    assert (sent["model"], sent["effort"]) == ("muse-spark-1.3", "low")
    assert sent["tools"] == [PAY_BILL_TOOL]
    assert sent["instructions"] == INSTRUCTIONS
    assert ("to", "acme-991") in proposal.call.args
    assert proposal.call_id == "call_1"
    assert proposal.trace == TRACE
    assert proposal.anchor == ReasoningAnchor(
        v=1, model="muse-spark-1.3", response_id="resp_1", blobs=("E1",)
    )
    assert proposal.reasoning_commitment == ANCHOR_1
    assert proposal.rationale == "Paying Acme."
    assert proposal.transcript == (*sent["input"], *output)


@pytest.mark.parametrize(
    ("output", "match"),
    [
        ([REASONING, message("I can't pay this.")], "no payment proposed"),
        ([tool_call(), tool_call(call_id="call_2")], "2 payments proposed"),
    ],
)
def test_propose_payment_requires_exactly_one_call(fake_meta, output, match):
    with pytest.raises(ProposalError, match=match):
        propose_payment(
            fake_meta(output), b"%PDF", "acme.pdf", "Pay.", source="checking-881"
        )


def test_report_outcome_replays_transcript_with_tool_result(fake_meta):
    meta = fake_meta([REASONING, tool_call()], [message("Paid $200 to Acme.")])
    proposal = propose_payment(meta, b"%PDF", "acme.pdf", "Pay.", source="checking-881")
    resp = report_outcome(meta, proposal, {"status": "executed", "payment": "pay:1"})
    replay = meta.requests[1]["input"]
    assert replay[:-1] == list(proposal.transcript)
    assert REASONING in replay
    assert replay[-1] == {
        "type": "function_call_output",
        "call_id": "call_1",
        "output": '{"payment": "pay:1", "status": "executed"}',
    }
    assert meta.requests[1]["tools"] == [PAY_BILL_TOOL]
    assert resp.text == "Paid $200 to Acme."


def test_call_from_tool_rejects_model_chosen_source():
    fn = tool_call(dict(ARGS, from_account="savings-002"))
    with pytest.raises(ProposalError, match="unexpected fields: from_account"):
        call_from_tool(fn, "checking-881", evidence_refs=())


def test_call_from_tool_rejects_empty_source():
    with pytest.raises(ProposalError, match="source must be a non-empty string"):
        call_from_tool(tool_call(), "", evidence_refs=())


def test_pay_bill_tool_has_no_source_account():
    schema = PAY_BILL_TOOL["parameters"]
    assert list(schema["properties"]) == [
        "to_account",
        "amount_cents",
        "currency",
        "reference",
    ]
    assert schema["required"] == list(schema["properties"])


def test_propose_payment_rejects_redacted_reasoning(fake_meta):
    redacted = {"type": "reasoning", "id": "rs_1", "summary": [], "status": "completed"}
    meta = fake_meta([redacted, tool_call()])
    with pytest.raises(MetaAPIError, match="response undecodable"):
        propose_payment(meta, b"%PDF", "acme.pdf", "Pay.", source="checking-881")


def test_proposal_rejects_drifted_commitment(fake_meta):
    meta = fake_meta([REASONING, tool_call()])
    proposal = propose_payment(meta, b"%PDF", "acme.pdf", "Pay.", source="checking-881")
    with pytest.raises(ValueError, match="commitment does not match anchor"):
        dataclasses.replace(proposal, reasoning_commitment="00" * 32)
    other = dataclasses.replace(proposal.anchor, response_id="resp_2")
    with pytest.raises(ValueError, match="commitment does not match anchor"):
        dataclasses.replace(proposal, anchor=other, reasoning_commitment=other.digest())
