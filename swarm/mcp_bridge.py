"""Bridge from MCP tools to the Responses API function-calling loop."""

import json
from typing import Any

from mcp import Client
from mcp.types import TextContent

from swarm.agent import MODEL, Responder
from swarm.meta_client import Item

DESK_INSTRUCTIONS = (
    "You operate the Mandate payment desk. Use only its tools. "
    "A payment is done only when confirm_payment returns status confirmed."
)


async def mcp_tools(client: Client) -> list[Item]:
    """List the server's MCP tools as Responses API function definitions."""
    listed = await client.list_tools()
    return [
        {
            "type": "function",
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema,
        }
        for tool in listed.tools
    ]


async def run_agent(
    meta: Responder,
    client: Client,
    request: str,
    *,
    model: str = MODEL,
    max_steps: int = 6,
    effort: str = "low",
) -> list[dict[str, Any]]:
    """Let the model drive the MCP tools until it stops calling them.

    Args:
        meta: Responses API client.
        client: Connected MCP client.
        request: User request text.
        model: Model id.
        max_steps: Maximum number of model turns.
        effort: Reasoning effort.

    Returns:
        One step per executed tool call: tool, parsed arguments and result.
    """
    tools = await mcp_tools(client)
    items: list[Item] = [{"role": "user", "content": request}]
    steps: list[dict[str, Any]] = []
    for _ in range(max_steps):
        # Blocking is acceptable: the desk runs in another thread or is in-memory.
        # The copy keeps a recording responder from seeing later appends.
        resp = meta.respond(
            model,
            list(items),
            tools=tools,
            instructions=DESK_INSTRUCTIONS,
            effort=effort,
        )
        items.extend(resp.output)
        if not resp.function_calls:
            break
        for call in resp.function_calls:
            step, output = await _execute(client, call)
            steps.append(step)
            call_id = call.get("call_id")
            if isinstance(call_id, str) and call_id:
                items.append(
                    {
                        "type": "function_call_output",
                        "call_id": call_id,
                        "output": output,
                    }
                )
    return steps


async def _execute(client: Client, call: Item) -> tuple[dict[str, Any], str]:
    """Run one model-proposed call; malformed input becomes an error step."""
    name = call.get("name")
    raw = call.get("arguments")
    try:
        if not isinstance(name, str) or not name:
            raise ValueError("missing tool name")
        if not isinstance(call.get("call_id"), str) or not call["call_id"]:
            raise ValueError("missing call id")
        arguments = json.loads(raw) if isinstance(raw, str) else None
        if not isinstance(arguments, dict):
            raise ValueError("arguments are not a JSON object")
    except ValueError as exc:
        return _failed(name, raw, f"bad tool call: {exc}")
    try:
        outcome = await client.call_tool(name, arguments)
    except Exception as exc:  # noqa: BLE001 - server and validation errors vary
        return _failed(name, arguments, f"bad tool call: {type(exc).__name__}")
    text = "".join(b.text for b in outcome.content if isinstance(b, TextContent))
    result: dict[str, Any]
    if outcome.is_error:
        result = {"error": text}
    else:
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        result = (
            parsed if isinstance(parsed, dict) else {"error": "non-JSON tool result"}
        )
    return {"tool": name, "arguments": arguments, "result": result}, text


def _failed(name: Any, arguments: Any, reason: str) -> tuple[dict[str, Any], str]:
    step = {"tool": name, "arguments": arguments, "result": {"error": reason}}
    return step, reason
