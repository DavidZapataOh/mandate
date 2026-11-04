"""Drive the payment desk over MCP the way an agent does (browser e2e helper)."""

import argparse
import asyncio
from typing import Any

from mcp import Client
from mcp.types import TextContent


async def _call(url: str, tool: str, args: dict[str, Any]) -> str:
    async with Client(url) as client:
        result = await client.call_tool(tool, args)
    first = result.content[0]
    if result.is_error or not isinstance(first, TextContent):
        raise SystemExit(f"desk tool failed: {tool}")
    return first.text


def main(argv: list[str] | None = None) -> None:
    """Print the desk's JSON answer to one quote or confirm call."""
    parser = argparse.ArgumentParser(prog="desk_agent")
    parser.add_argument("url", help="the desk's MCP endpoint, e.g. http://h:p/mcp")
    sub = parser.add_subparsers(dest="tool", required=True)
    quote = sub.add_parser("quote")
    quote.add_argument("to_account")
    quote.add_argument("amount_cents", type=int)
    quote.add_argument("currency")
    quote.add_argument("reference")
    confirm = sub.add_parser("confirm")
    confirm.add_argument("quote_id")
    args = parser.parse_args(argv)
    if args.tool == "quote":
        tool = "quote_payment"
        call: dict[str, Any] = {
            "to_account": args.to_account,
            "amount_cents": args.amount_cents,
            "currency": args.currency,
            "reference": args.reference,
        }
    else:
        tool, call = "confirm_payment", {"quote_id": args.quote_id}
    print(asyncio.run(_call(args.url, tool, call)), flush=True)


if __name__ == "__main__":
    main()
