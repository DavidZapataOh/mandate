import json

import pytest
from mcp import Client
from mcp.types import CallToolResult, ImageContent, TextContent

from swarm.conftest import ARGS, REASONING, message, tool_call
from swarm.mcp_bridge import DESK_INSTRUCTIONS, mcp_tools, run_agent
from swarm.server import build_server

TOOLS = ["confirm_payment", "get_payment_status", "get_receipt", "quote_payment"]


@pytest.mark.anyio
async def test_mcp_tools_become_responses_functions(make_desk):
    desk, _ = make_desk()
    async with Client(build_server(desk, "unused")) as client:
        tools = {t["name"]: t for t in await mcp_tools(client)}
    assert sorted(tools) == TOOLS
    assert tools["quote_payment"]["type"] == "function"
    assert tools["quote_payment"]["parameters"]["required"] == [
        "to_account",
        "amount_cents",
        "currency",
        "reference",
    ]
    assert "account holder approves" in tools["confirm_payment"]["description"]


@pytest.mark.anyio
async def test_run_agent_executes_and_replays(make_desk, fake_meta):
    desk, _ = make_desk()
    meta = fake_meta(
        [REASONING, tool_call(ARGS, name="quote_payment")],
        [message("Quoted q:000001.")],
    )
    async with Client(build_server(desk, "unused")) as client:
        steps = await run_agent(meta, client, "Quote invoice A-991.")
    assert [(s["tool"], s["arguments"]) for s in steps] == [("quote_payment", ARGS)]
    assert steps[0]["result"]["status"] == "quoted"
    first, second = meta.requests
    assert first["instructions"] == DESK_INSTRUCTIONS
    assert sorted(t["name"] for t in first["tools"]) == TOOLS
    replay = second["input"]
    assert replay[0] == {"role": "user", "content": "Quote invoice A-991."}
    assert [item["type"] for item in replay[1:]] == [
        "reasoning",
        "function_call",
        "function_call_output",
    ]
    assert replay[3]["call_id"] == "call_1"
    assert json.loads(replay[3]["output"])["quote_id"] == "q:000001"


@pytest.mark.anyio
async def test_run_agent_reports_tool_errors(make_desk, fake_meta):
    desk, _ = make_desk()
    bad = dict(ARGS, amount_cents="lots")
    meta = fake_meta([tool_call(bad, name="quote_payment")], [message("Failed.")])
    async with Client(build_server(desk, "unused")) as client:
        steps = await run_agent(meta, client, "Quote it.")
    assert list(steps[0]["result"]) == ["error"]
    assert desk.pending() == []


@pytest.mark.anyio
async def test_run_agent_stops_at_max_steps(make_desk, fake_meta):
    desk, _ = make_desk()
    status = tool_call({"quote_id": "q:000001"}, name="get_payment_status")
    meta = fake_meta([status], [status], [status])
    async with Client(build_server(desk, "unused")) as client:
        steps = await run_agent(meta, client, "Loop.", max_steps=2)
    assert (len(steps), len(meta.requests)) == (2, 2)


@pytest.mark.anyio
@pytest.mark.parametrize("raw", ["{bad", "[1]", '"s"'])
async def test_run_agent_survives_malformed_arguments(make_desk, fake_meta, raw):
    desk, _ = make_desk()
    call = dict(tool_call(name="quote_payment"), arguments=raw)
    meta = fake_meta([call], [message("Done.")])
    async with Client(build_server(desk, "unused")) as client:
        steps = await run_agent(meta, client, "Quote it.")
    assert [(s["tool"], s["arguments"]) for s in steps] == [("quote_payment", raw)]
    assert list(steps[0]["result"]) == ["error"]
    assert len(meta.requests) == 2
    assert meta.requests[1]["input"][-1]["type"] == "function_call_output"
    assert desk.pending() == []


@pytest.mark.anyio
async def test_run_agent_survives_missing_call_id(make_desk, fake_meta):
    desk, _ = make_desk()
    call = tool_call(ARGS, name="quote_payment")
    del call["call_id"]
    meta = fake_meta([call], [message("Done.")])
    async with Client(build_server(desk, "unused")) as client:
        steps = await run_agent(meta, client, "Quote it.")
    assert list(steps[0]["result"]) == ["error"]
    assert desk.pending() == []
    types = [i.get("type") for i in meta.requests[1]["input"]]
    assert "function_call_output" not in types


class StubClient:
    def __init__(self, content, is_error=False):
        self.result = CallToolResult(content=content, is_error=is_error)

    async def list_tools(self):
        class Listed:
            tools = []

        return Listed()

    async def call_tool(self, name, arguments):
        return self.result


@pytest.mark.anyio
@pytest.mark.parametrize(
    "content",
    [
        [],
        [ImageContent(type="image", data="AA==", mime_type="image/png")],
        [TextContent(type="text", text="not json")],
        [TextContent(type="text", text="[1]")],
    ],
)
async def test_run_agent_survives_odd_tool_results(fake_meta, content):
    meta = fake_meta([tool_call(ARGS, name="quote_payment")], [message("Done.")])
    steps = await run_agent(meta, StubClient(content), "Quote it.")
    assert list(steps[0]["result"]) == ["error"]
    assert len(meta.requests) == 2


@pytest.mark.anyio
async def test_run_agent_survives_error_without_body(fake_meta):
    meta = fake_meta([tool_call(ARGS, name="quote_payment")], [message("Done.")])
    steps = await run_agent(meta, StubClient([], is_error=True), "Quote it.")
    assert steps[0]["result"] == {"error": ""}
