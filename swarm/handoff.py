"""Hand a signed intent id to Muse Spark, which quotes, waits, then confirms."""

import threading
import time
from collections.abc import Callable
from typing import Any

import anyio
import anyio.to_thread
from mcp import Client
from mcp.server import MCPServer

from swarm.agent import Responder
from swarm.desk import PaymentDesk
from swarm.mcp_bridge import run_agent
from swarm.meta_client import MetaAPIError

QUOTE_REQUEST = (
    "The account holder signed payment intent {intent_id}. Read it with "
    "get_intent and quote exactly that payment with quote_payment. "
    "Do not confirm."
)
CONFIRM_REQUEST = (
    "The account holder approved quote {quote_id}. Confirm it with confirm_payment."
)
_RUNNING = ("quoting", "waiting", "confirming")


class AgentHandoff:
    """Runs Muse Spark through one payment, one run at a time.

    The model sees the intent id and the desk's tool results, nothing the
    holder said or signed.

    Args:
        meta: Model that drives the desk's tools.
        server: The desk's MCP server, reached in memory.
        desk: Desk the run is judged against.
        poll_s: Seconds between looks at the quote while the holder decides.
        wait_s: Seconds the holder has to approve before the run gives up.
        sleep: Blocking sleep; injectable for tests.
        clock: Monotonic clock in seconds; injectable for tests.
    """

    def __init__(
        self,
        meta: Responder,
        server: MCPServer,
        desk: PaymentDesk,
        poll_s: float = 0.5,
        wait_s: float = 600.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._meta = meta
        self._server = server
        self._desk = desk
        self._poll_s = poll_s
        self._wait_s = wait_s
        self._sleep = sleep
        self._clock = clock
        self._lock = threading.Lock()
        self._status: dict[str, Any] = {
            "state": "idle",
            "intent_id": None,
            "quote_id": None,
            "detail": "",
        }

    def status(self) -> dict[str, Any]:
        """Return a copy of the current run's status."""
        with self._lock:
            return dict(self._status)

    def start(self, intent_id: str) -> dict[str, Any]:
        """Start a run for a signed intent.

        Args:
            intent_id: Id of an intent the holder signed and the desk has not
                yet paid.

        Returns:
            The new status, or ``{"error": ...}`` for an unknown intent or
            while another run is under way.
        """
        if self._desk.intent_receipt(intent_id).get("status") != "signed":
            return {"error": "unknown intent"}
        with self._lock:
            if self._status["state"] in _RUNNING:
                return {"error": "busy"}
            self._status = {
                "state": "quoting",
                "intent_id": intent_id,
                "quote_id": None,
                "detail": (
                    f"Muse Spark is quoting intent {intent_id}; it holds only this id."
                ),
            }
            started = dict(self._status)
        threading.Thread(target=self._run, args=(intent_id,), daemon=True).start()
        return started

    def _set(self, state: str, detail: str, quote_id: str | None = None) -> None:
        with self._lock:
            self._status = {
                **self._status,
                "state": state,
                "detail": detail,
                "quote_id": quote_id or self._status["quote_id"],
            }

    def _run(self, intent_id: str) -> None:
        try:
            anyio.run(self._drive, intent_id)
        except Exception:  # noqa: BLE001 - a dead run must free the slot
            self._set("failed", "Muse Spark run failed.")

    async def _drive(self, intent_id: str) -> None:
        async with Client(self._server) as client:
            # Caught inside the client: its task group would wrap the error.
            try:
                await self._pay(client, intent_id)
            except MetaAPIError as err:
                self._set("failed", f"Muse Spark call failed: {err}")

    async def _pay(self, client: Client, intent_id: str) -> None:
        steps = await run_agent(
            self._meta, client, QUOTE_REQUEST.format(intent_id=intent_id)
        )
        quote_id = _quote_id(steps)
        if quote_id is None:
            self._set("failed", f"Muse Spark did not quote intent {intent_id}.")
            return
        self._set(
            "waiting", f"Quote {quote_id} is waiting for your approval.", quote_id
        )
        decided = await anyio.to_thread.run_sync(self._await_decision, quote_id)
        if decided != "approved":
            self._set("failed", f"Quote {quote_id} was not approved: {decided}.")
            return
        self._set("confirming", f"Muse Spark is confirming quote {quote_id}.")
        await run_agent(self._meta, client, CONFIRM_REQUEST.format(quote_id=quote_id))
        outcome = self._desk.status(quote_id)
        if outcome["status"] == "confirmed":
            self._set("done", f"Paid: {outcome['payment_id']}.")
        else:
            reason = outcome.get("reason") or outcome["status"]
            self._set("failed", f"Not paid: {reason}.")

    def _await_decision(self, quote_id: str) -> str:
        deadline = self._clock() + self._wait_s
        while True:
            status = str(self._desk.status(quote_id)["status"])
            if status != "quoted" or self._clock() >= deadline:
                return status
            self._sleep(self._poll_s)


def _quote_id(steps: list[dict[str, Any]]) -> str | None:
    quotes = [s["result"] for s in steps if s["tool"] == "quote_payment"]
    if quotes and quotes[-1].get("status") == "quoted":
        quote_id = quotes[-1].get("quote_id")
        return quote_id if isinstance(quote_id, str) else None
    return None
