import os
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
from mcp import Client

from e2e.test_explorer_walkthrough import (
    CLI,
    CONSOLE,
    PAIR,
    _free_port,
    _missing,
    _pair,
    _pay_as,
    _tool,
)

READS = ("/api/keys", "/api/receipt/pay:000001?disclose=all", "/api/registry")


class _Console:
    """One `mandate-console` on a fixed port and state directory."""

    def __init__(self, state_dir: Path) -> None:
        self.url = f"http://127.0.0.1:{_free_port()}"
        self.state_dir = state_dir
        self._proc: subprocess.Popen[str] | None = None
        self.token = ""

    def start(self) -> None:
        port = self.url.rsplit(":", 1)[1]
        self._proc = subprocess.Popen(  # noqa: S603
            [
                str(CLI),
                "--port",
                port,
                "--console-dir",
                str(CONSOLE / "dist"),
                "--state-dir",
                str(self.state_dir),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self._proc.stdout is not None
        found = PAIR.fullmatch(self._proc.stdout.readline().strip())
        assert found is not None
        self.token = found.group(1)
        deadline = time.monotonic() + 15
        while True:
            try:
                httpx2.get(f"{self.url}/api/keys")
                return
            except httpx2.TransportError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            self._proc.wait(10)
            self._proc = None


@pytest.fixture
def console(tmp_path: Path) -> Iterator[_Console]:
    missing = _missing()
    if missing is not None:
        if os.environ.get("MANDATE_WALKTHROUGH") == "1":
            pytest.fail(f"walkthrough: {missing}")
        pytest.skip(f"walkthrough: {missing}")
    served = _Console(tmp_path / "state")
    served.start()
    try:
        yield served
    finally:
        served.stop()


def _reads(url: str) -> list[Any]:
    return [httpx2.get(f"{url}{path}").json() for path in READS]


async def _status(url: str, quote_id: str) -> dict[str, Any]:
    async with Client(f"{url}/mcp") as client:
        return await _tool(client, "get_payment_status", {"quote_id": quote_id})


def _run(fn: Callable[..., Any], *args: Any) -> Any:
    return anyio.run(fn, *args)


def test_a_restarted_console_keeps_its_receipts_and_fences(console: _Console) -> None:
    holder = _run(_pair, console.url, console.token)
    first = _run(_pay_as, console.url, holder)
    assert (first["payment_id"], first["reason"]) == ("pay:000001", "ok: executed")
    before = _reads(console.url)
    console.stop()
    # A clean stop folds the write-ahead log into state.db: that one file
    # is the copy an auditor needs.
    assert not (console.state_dir / "state.db-wal").exists()
    console.start()
    assert _reads(console.url) == before
    provenance = httpx2.get(f"{console.url}/api/provenance").json()
    assert provenance["registry"]["leaves"] == 1
    second = _run(_pay_as, console.url, holder)
    assert (second["payment_id"], second["reason"]) == ("pay:000002", "ok: executed")
    assert _run(_status, console.url, "q:000001")["status"] == "confirmed"
