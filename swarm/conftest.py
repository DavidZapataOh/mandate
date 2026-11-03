"""Test-only fixtures for the Meta agent."""

import json

import pytest

from swarm.meta_client import MetaResponse, MetaTrace

TRACE = MetaTrace(
    model="muse-spark-1.3",
    response_id="resp_1",
    request_id="req-1",
    latency_ms=4960.4,
    input_tokens=3215,
    output_tokens=251,
)
ARGS = {
    "amount_cents": 20000,
    "currency": "USD",
    "reference": "A-991",
    "to_account": "acme-991",
}
REASONING = {
    "id": "rs_1",
    "summary": [],
    "type": "reasoning",
    "encrypted_content": "E1",
    "status": "completed",
}


def message(text: str) -> dict:
    return {
        "id": "msg_1",
        "content": [
            {"annotations": [], "text": text, "type": "output_text", "logprobs": []}
        ],
        "role": "assistant",
        "status": "completed",
        "type": "message",
        "phase": "commentary",
    }


def tool_call(args=None, name="pay_bill", call_id="call_1") -> dict:
    return {
        "arguments": json.dumps(ARGS if args is None else args),
        "call_id": call_id,
        "name": name,
        "type": "function_call",
        "id": "fc_" + call_id,
        "status": "completed",
    }


class FakeMeta:
    """Test fake for MetaClient.respond: queued outputs, recorded requests.

    A queued output that is an Exception instance is raised instead of returned.
    """

    def __init__(self, *outputs):
        self.outputs = list(outputs)
        self.requests = []

    def respond(
        self,
        model,
        input,
        *,
        tools=(),
        instructions=None,
        effort="medium",
        text_format=None,
    ):
        self.requests.append(
            {
                "model": model,
                "input": input,
                "tools": list(tools),
                "instructions": instructions,
                "effort": effort,
                "text_format": text_format,
            }
        )
        output = self.outputs.pop(0)
        if isinstance(output, Exception):
            raise output
        return MetaResponse(trace=TRACE, output=tuple(output))


@pytest.fixture
def fake_meta():
    return FakeMeta
