"""Test-only attack world: one served mandate-console and the parties around it.

Every attack in the e2e suite reaches Mandate the way its attacker would: over
the console's own socket, as an MCP client (the agent), an HTTP client (a
page, a device, a neighbour on the network) or a holder device with a key.
"""

import base64
import json
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import anyio
import httpx2
from mcp import Client
from mcp.types import TextContent

from gate.certs import generate_keypair
from gate.consent import Consent, HolderApproval, sign_approval

ROOT = Path(__file__).resolve().parent.parent
# The console's own entry point, imported from this tree so a weakened copy
# of the tree runs its own weakened code.
CONSOLE_CMD = (sys.executable, "-c", "from swarm.console import cli; cli()")
PAIR = re.compile(r"Pair the holder device: \S+/app/#pair=(\S+)")
QUOTE = {
    "to_account": "acme-991",
    "amount_cents": 20000,
    "currency": "USD",
    "reference": "A-991",
}
START_S = 15


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def approval_body(quote_id: str, approval: HolderApproval) -> dict[str, str]:
    return {
        "quote_id": quote_id,
        "signature": b64(approval.signature),
        "consent_key": b64(approval.consent_key),
        "key_signature": b64(approval.key_signature),
    }


def unsigned(quote: dict[str, Any]) -> Consent:
    return Consent(**quote["consent"], signature=b"")


class Console:
    """One mandate-console process on a free port, simulated rail.

    Args:
        tmp: Private directory for the console build stub and the state.
        durable: Keep the gate key and fences in ``tmp / "state"``.
        local_port: Run with ``--local-port`` on a second free port, so
            ``/mcp`` and holder copies answer only on ``local_url``.
        extra: More console flags, appended as given.
    """

    def __init__(
        self,
        tmp: Path,
        durable: bool = True,
        local_port: bool = False,
        extra: tuple[str, ...] = (),
    ) -> None:
        dist = tmp / "dist"
        dist.mkdir(parents=True, exist_ok=True)
        (dist / "index.html").write_text("<!doctype html><title>Mandate</title>")
        self.url = f"http://127.0.0.1:{free_port()}"
        self.state_dir = tmp / "state"
        self._args = ["--port", self.url.rsplit(":", 1)[1], "--console-dir", str(dist)]
        if durable:
            self._args += ["--state-dir", str(self.state_dir)]
        self.local_url = self.url
        if local_port:
            port = free_port()
            while self.url.endswith(f":{port}"):
                port = free_port()
            self.local_url = f"http://127.0.0.1:{port}"
            self._args += ["--local-port", self.local_url.rsplit(":", 1)[1]]
        self._args += extra
        self._proc: subprocess.Popen[str] | None = None
        self._drain_thread = threading.Thread()
        self.token = ""
        self.lines: list[str] = []

    def start(self) -> "Console":
        self._proc = subprocess.Popen(  # noqa: S603
            [*CONSOLE_CMD, *self._args],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            text=True,
        )
        first = self._proc.stdout.readline() if self._proc.stdout else ""
        found = PAIR.fullmatch(first.strip())
        if found is None:
            self._proc.kill()
            self._proc.wait(10)
            self._proc = None
            raise RuntimeError(f"console printed no pairing URL: {first!r}")
        self.token = found.group(1)
        # The console keeps printing (paired holders, the console URL); a pipe
        # nobody reads fills up and blocks the server mid-request.
        self.lines = [first]
        self._drain_thread = threading.Thread(target=self._drain, daemon=True)
        self._drain_thread.start()
        deadline = time.monotonic() + START_S
        while True:
            try:
                httpx2.get(f"{self.url}/api/keys")
                return self
            except httpx2.TransportError:
                if time.monotonic() > deadline:
                    self.stop()
                    raise
                time.sleep(0.05)

    def _drain(self) -> None:
        proc = self._proc
        if proc is not None and proc.stdout is not None:
            for line in proc.stdout:
                self.lines.append(line)

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            self._proc.wait(10)
            self._drain_thread.join(10)
            if self._proc.stdout is not None:
                self._proc.stdout.close()
            self._proc = None

    def get(self, path: str, **kw: Any) -> httpx2.Response:
        return httpx2.get(f"{self.url}{path}", **kw)

    def post(self, path: str, **kw: Any) -> httpx2.Response:
        return httpx2.post(f"{self.url}{path}", **kw)

    def tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Call one desk tool as the agent does, over MCP."""

        async def call() -> dict[str, Any]:
            async with Client(f"{self.local_url}/mcp") as client:
                outcome = await client.call_tool(name, args)
            text = "".join(
                b.text for b in outcome.content if isinstance(b, TextContent)
            )
            body: dict[str, Any] = json.loads(text)
            return body

        return anyio.run(call)

    def pair(self) -> bytes:
        """Pair a fresh holder device with the printed token; its private key."""
        holder_priv, holder_pub = generate_keypair()
        paired = self.post(
            "/api/holder", json={"public_key": b64(holder_pub), "pairing": self.token}
        )
        if paired.json() != {"registered": True}:
            raise RuntimeError(f"pairing refused: {paired.text}")
        return holder_priv

    def approve(
        self, quote: dict[str, Any], holder_priv: bytes, seed: bytes | None = None
    ) -> dict[str, Any]:
        approval = sign_approval(holder_priv, unsigned(quote), seed)
        body: dict[str, Any] = self.post(
            "/api/approve", json=approval_body(quote["quote_id"], approval)
        ).json()
        return body

    def pay(self, holder_priv: bytes, seed: bytes | None = None) -> dict[str, Any]:
        quote = self.tool("quote_payment", QUOTE)
        approved = self.approve(quote, holder_priv, seed)
        if approved["status"] != "approved":
            raise RuntimeError(f"approval refused: {approved}")
        return self.tool("confirm_payment", {"quote_id": quote["quote_id"]})
