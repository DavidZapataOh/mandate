"""Pays one real desk quote end to end against a running console server.

Usage: desk_payment.py BASE_URL PAIRING_TOKEN. Pairs a fresh holder key, quotes
through MCP, signs the holder consent and approves, prints `approved`, then
confirms once a line arrives on stdin and prints the confirm status.
"""

import asyncio
import base64
import json
import sys
from typing import Any

import httpx2
from mcp import Client
from mcp.types import TextContent

from gate.certs import generate_keypair
from gate.consent import Consent, sign_consent

QUOTE = {
    "to_account": "acme-991",
    "amount_cents": 4200,
    "currency": "USD",
    "reference": "INV-42",
}


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


async def _tool(client: Client, name: str, args: dict[str, Any]) -> dict[str, Any]:
    outcome = await client.call_tool(name, args)
    text = "".join(b.text for b in outcome.content if isinstance(b, TextContent))
    body: dict[str, Any] = json.loads(text)
    return body


async def pay(base: str, pairing: str) -> str:
    """Runs the holder-approved payment and returns the confirm status."""
    private, public = generate_keypair()
    paired = httpx2.post(
        f"{base}/api/holder", json={"public_key": _b64(public), "pairing": pairing}
    )
    paired.raise_for_status()
    async with Client(f"{base}/mcp") as client:
        quoted = await _tool(client, "quote_payment", QUOTE)
        consent = Consent(**quoted["consent"], signature=b"")
        signature = sign_consent(private, consent).signature
        approved = httpx2.post(
            f"{base}/api/approve",
            json={"quote_id": quoted["quote_id"], "signature": _b64(signature)},
        )
        approved.raise_for_status()
        print("approved", flush=True)
        # The caller decides when the confirmation lands relative to its other events.
        await asyncio.to_thread(sys.stdin.readline)
        done = await _tool(client, "confirm_payment", {"quote_id": quoted["quote_id"]})
    return str(done["status"])


if __name__ == "__main__":
    print(asyncio.run(pay(sys.argv[1], sys.argv[2])))
