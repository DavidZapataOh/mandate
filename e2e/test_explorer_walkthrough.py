import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
from mcp import Client
from mcp.types import TextContent

from gate.certs import generate_keypair
from gate.consent import Consent, sign_approval

CONSOLE = Path(__file__).resolve().parent.parent / "console"
CLI = Path(sys.executable).parent / "mandate-console"
PAIR = re.compile(r"Pair the holder device: http://127\.0\.0\.1:\d+/app/#pair=(\S+)")
WALKTHROUGH = (
    "npx",
    "playwright",
    "test",
    "--config",
    "playwright.walkthrough.config.ts",
)
QUOTE = {
    "to_account": "acme-991",
    "amount_cents": 20000,
    "currency": "USD",
    "reference": "A-991",
}


def _missing() -> str | None:
    if not CLI.exists():
        return "mandate-console is not installed"
    if not (CONSOLE / "dist" / "explorer.html").exists():
        return "console build missing: run npm run build in console/"
    if shutil.which("npx") is None:
        return "npx is not on PATH"
    return None


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def console() -> Iterator[tuple[str, str]]:
    missing = _missing()
    if missing is not None:
        if os.environ.get("MANDATE_WALKTHROUGH") == "1":
            pytest.fail(f"walkthrough: {missing}")
        pytest.skip(f"walkthrough: {missing}")
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603
        [str(CLI), "--port", str(port), "--console-dir", str(CONSOLE / "dist")],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        found = PAIR.fullmatch(proc.stdout.readline().strip())
        assert found is not None
        url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 15
        while True:
            try:
                httpx2.get(f"{url}/api/keys")
                break
            except httpx2.TransportError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        yield url, found.group(1)
    finally:
        proc.terminate()
        proc.wait(10)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


async def _tool(client: Client, name: str, args: dict[str, Any]) -> dict[str, Any]:
    outcome = await client.call_tool(name, args)
    text = "".join(b.text for b in outcome.content if isinstance(b, TextContent))
    body: dict[str, Any] = json.loads(text)
    return body


async def _pair(url: str, token: str) -> bytes:
    holder_priv, holder_pub = generate_keypair()
    async with httpx2.AsyncClient(base_url=url) as http:
        paired = await http.post(
            "/api/holder", json={"public_key": _b64(holder_pub), "pairing": token}
        )
    assert paired.json() == {"registered": True}
    return holder_priv


async def _pay(url: str, token: str) -> dict[str, Any]:
    return await _pay_as(url, await _pair(url, token))


async def _pay_as(url: str, holder_priv: bytes) -> dict[str, Any]:
    async with httpx2.AsyncClient(base_url=url) as http:
        async with Client(f"{url}/mcp") as client:
            quote = await _tool(client, "quote_payment", QUOTE)
            consent = Consent(**quote["consent"], signature=b"")
            approval = sign_approval(holder_priv, consent)
            approved = await http.post(
                "/api/approve",
                json={
                    "quote_id": quote["quote_id"],
                    "signature": _b64(approval.signature),
                    "consent_key": _b64(approval.consent_key),
                    "key_signature": _b64(approval.key_signature),
                },
            )
            assert approved.json()["status"] == "approved"
            return await _tool(
                client, "confirm_payment", {"quote_id": quote["quote_id"]}
            )


def test_a_fresh_payment_verifies_in_the_explorer(console: tuple[str, str]) -> None:
    url, token = console
    done = anyio.run(_pay, url, token)
    assert (done["status"], done["reason"]) == ("confirmed", "ok: executed")
    run = subprocess.run(  # noqa: S603
        WALKTHROUGH,
        cwd=CONSOLE,
        env={**os.environ, "MANDATE_URL": url, "MANDATE_PAYMENT": done["payment_id"]},
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert run.returncode == 0, run.stdout[-3000:] + run.stderr[-2000:]
    assert "4 passed" in run.stdout
