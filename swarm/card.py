"""Mandate as the bank's card authorizer: one signed webhook, one answer in time."""

import functools
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import uvicorn
from increase import Increase
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from bank.card import (
    CARD_DEADLINE_S,
    CARD_GATE_S,
    CARD_SAFETY_S,
    DEADLINE_PASSED,
    MALFORMED,
    MAX_WEBHOOK_BODY,
    NOT_A_CARD_AUTHORIZATION,
    NOT_PENDING,
    CardAuthorization,
    CardDecisionRail,
    CardWebhookError,
    decline,
    read_authorization,
    webhook_decision_id,
    within_budget,
)
from gate.state import StateStore
from swarm.console_line import card_summary
from swarm.desk import PaymentDesk

WEBHOOK_PATH = "/increase/card-authorizations"
CARD_DECISION_KIND = "card_decision"
CARD_DECISION_TTL_S = 86_400

APPROVED = "approved"
DECLINED = "declined"
NOT_ANSWERED = "not_answered"
UNKNOWN = "unknown"

_UNREADABLE = "card: unreadable"
_OTHER_CARD = "card: not the agent card"
_NO_QUOTE = "card: no approved quote"
_BUSY = "card: desk busy"
_TWO_STEP = "card: two-step desk"
_HELD = "card: held at the bank"
_REGISTRY_FULL = "registry: full"
# Connections the loopback listener serves at once; the rest get a 503.
_MAX_CONNECTIONS = 16
_OUTCOME_UNKNOWN = "bank: outcome unknown"
_TOO_LARGE = "webhook: too large"
# Refusals from the desk that sealed nothing, so the card answer seals one.
_UNSEALED = (_BUSY, _TWO_STEP, _REGISTRY_FULL, _NO_QUOTE, _HELD)

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CardOutcome:
    """Mandate's answer to one card authorization.

    Args:
        decision_id: The bank's real-time decision id.
        status: ``approved``, ``declined``, ``not_answered`` or ``unknown``.
        reason: Why.
        quote_id: The quote the authorization matched, or None.
        sealed: Whether a confirm sealed this answer in the registry.
    """

    decision_id: str
    status: str
    reason: str
    quote_id: str | None
    sealed: bool


class CardAuthorizer:
    """Answer each of the bank's card decisions once, inside its deadline.

    The local deadline is measured on a monotonic clock from receipt and
    expressed in wall-clock time anchored at receipt, the frame of the
    bank's ``timeout_at``; a wall clock that jumps never stretches it.

    Args:
        client: Increase client pinned to the sandbox.
        desk: The payment desk whose approved quotes a card may spend.
        card_id: The agent card's bank id.
        account_id: The bank's id for the desk's debit account.
        state: Durable store; each decision id is spent in it once.
        clock: Wall-clock time in unix seconds.
        monotonic: A clock that never goes backwards, in seconds.
    """

    def __init__(
        self,
        client: Increase,
        desk: PaymentDesk,
        card_id: str,
        account_id: str,
        state: StateStore,
        clock: Callable[[], float] = time.time,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        # A resent read could eat the deadline the answer needs.
        self._client = client.with_options(max_retries=0)
        self._desk = desk
        self._card_id = card_id
        self._account_id = account_id
        self._state = state
        self._clock = clock
        self._monotonic = monotonic

    def stamp(self) -> tuple[float, float]:
        """The moment of receipt: wall-clock and monotonic time, read together."""
        return (self._clock(), self._monotonic())

    def handle(
        self, decision_id: str, *, received: tuple[float, float] | None = None
    ) -> CardOutcome | None:
        """Read one decision from the bank and approve or decline it in time.

        Args:
            decision_id: The decision id a verified webhook named.
            received: ``stamp()`` taken when the webhook arrived; None means
                now. Time spent reading and verifying counts against the
                deadline.

        Returns:
            Mandate's answer, or None when this decision was already handled.
        """
        wall, started = self.stamp() if received is None else received

        def now() -> float:
            return wall + (self._monotonic() - started)

        expires = int(wall) + CARD_DECISION_TTL_S
        if not self._state.consume(CARD_DECISION_KIND, decision_id, expires):
            return None
        cap = wall + CARD_DEADLINE_S
        try:
            read = self._client.real_time_decisions.retrieve(
                decision_id,
                timeout=within_budget(max(cap - CARD_SAFETY_S - now(), 0.001)),
            )
        except Exception:
            answer = self._decline(decision_id, cap, now, _UNREADABLE)
            return self._finish(decision_id, None, answer)
        try:
            auth = read_authorization(read)
        except ValueError as exc:
            if str(exc) == NOT_PENDING:
                return self._finish(decision_id, None, (NOT_ANSWERED, NOT_PENDING))
            answer = self._decline(decision_id, cap, now, str(exc))
            return self._finish(decision_id, None, answer)
        if auth.decision_id != decision_id:
            # Approving it would answer a decision never consumed here.
            answer = self._decline(decision_id, cap, now, MALFORMED)
            return self._finish(decision_id, None, answer)
        # A decision claiming a later deadline cannot buy time.
        deadline = min(auth.timeout_at, cap)
        if (auth.card_id, auth.account_id) != (self._card_id, self._account_id):
            answer = self._decline(decision_id, deadline, now, _OTHER_CARD)
            return self._finish(decision_id, auth, answer)
        # With no time left for the gate before the safety margin, nothing
        # touches the desk: the quote stays the holder's. A gate that starts
        # in time but runs past its allowance still closes the quote denied.
        if deadline - CARD_SAFETY_S - CARD_GATE_S - now() <= 0:
            answer = self._decline(decision_id, deadline, now, DEADLINE_PASSED)
            return self._finish(decision_id, auth, answer)
        try:
            quote_id = self._desk.card_quote(
                auth.merchant,
                auth.amount_cents,
                auth.currency,
                wait_s=deadline - CARD_SAFETY_S - CARD_GATE_S - now(),
            )
        except TimeoutError:
            answer = self._decline(decision_id, deadline, now, _BUSY)
            return self._finish(decision_id, auth, answer)
        if quote_id is None:
            answer = self._decline(decision_id, deadline, now, _NO_QUOTE)
            return self._finish(decision_id, auth, answer)
        rail = CardDecisionRail(
            self._client,
            auth,
            self._desk.source,
            self._account_id,
            deadline,
            now,
            card_id=self._card_id,
        )
        if rail.left() - CARD_GATE_S <= 0:
            answer = self._decline(decision_id, deadline, now, DEADLINE_PASSED)
            return self._finish(decision_id, auth, answer, quote_id)
        try:
            # The desk checks the time left again once it holds the lock and
            # just before the gate, and refuses unsealed when it is short.
            result = self._desk.authorize_card(
                quote_id,
                rail,
                rail.left() - CARD_GATE_S,
                time_left=rail.left,
                gate_s=CARD_GATE_S,
            )
        except Exception as exc:
            _log.error("card decision failed (%s)", type(exc).__name__)
            unknown = (UNKNOWN, _OUTCOME_UNKNOWN)
            return self._finish(decision_id, auth, unknown, quote_id)
        reason = str(result["reason"])
        sealed = reason not in _UNSEALED
        # Only this decision's own approval is an approval; a full registry
        # leaves no payment id at all.
        if result["status"] == "confirmed" and result.get("payment_id") == decision_id:
            answer = (APPROVED, reason)
        elif reason == _OUTCOME_UNKNOWN:
            answer = (UNKNOWN, _OUTCOME_UNKNOWN)
        elif result["status"] == "confirmed":
            # Unreachable while the read's id is checked above; kept as a fence.
            sealed = False
            answer = self._decline(decision_id, deadline, now, _NO_QUOTE)
        else:
            answer = self._decline(decision_id, deadline, now, reason)
        return self._finish(decision_id, auth, answer, quote_id, sealed)

    def _decline(
        self,
        decision_id: str,
        deadline: float,
        now: Callable[[], float],
        reason: str,
    ) -> tuple[str, str]:
        if decline(self._client, decision_id, deadline, now):
            return (DECLINED, reason)
        # Nothing posted in time: the bank's own default decline stands.
        return (NOT_ANSWERED, reason)

    def _finish(
        self,
        decision_id: str,
        auth: CardAuthorization | None,
        answer: tuple[str, str],
        quote_id: str | None = None,
        sealed: bool = False,
    ) -> CardOutcome:
        status, reason = answer
        if auth is None:
            summary = f"Card authorization {decision_id}"
        else:
            summary = card_summary(
                auth.amount_cents,
                auth.currency,
                auth.merchant,
                auth.descriptor,
                self._desk.source,
            )
        try:
            self._desk.record_card(
                decision_id, status, reason, quote_id, sealed, summary
            )
        except Exception as exc:
            # The bank already has its answer; only the record is missing.
            _log.error(
                "card record failed for %s (%s, %s)",
                decision_id,
                status,
                type(exc).__name__,
            )
        return CardOutcome(decision_id, status, reason, quote_id, sealed)


async def _capped(request: Request) -> bytes | None:
    """Read the body, or None as soon as it grows past the webhook cap."""
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_WEBHOOK_BODY:
            return None
    return bytes(body)


def _refused(reason: str, status_code: int) -> JSONResponse:
    _log.warning("card webhook refused (%s)", reason)
    return JSONResponse({"error": reason}, status_code=status_code)


def card_webhook_app(
    client: Increase, authorizer: CardAuthorizer, secret: str
) -> Starlette:
    """The bank's card authorization webhook, alone on its own app.

    Args:
        client: Increase client whose ``events.unwrap`` verifies signatures.
        authorizer: Answers each verified decision.
        secret: The secret shared with the bank's event subscription.

    Returns:
        A Starlette app with one route, ``POST /increase/card-authorizations``;
        it answers only after the bank has Mandate's action.
    """

    async def receive(request: Request) -> Response:
        received = authorizer.stamp()
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_WEBHOOK_BODY:
            return _refused(_TOO_LARGE, 413)
        body = await _capped(request)
        if body is None:
            return _refused(_TOO_LARGE, 413)
        try:
            decision_id = webhook_decision_id(client, body, request.headers, secret)
        except CardWebhookError as exc:
            reason = str(exc)
            return _refused(reason, 400 if reason == NOT_A_CARD_AUTHORIZATION else 401)
        try:
            outcome = await run_in_threadpool(
                functools.partial(authorizer.handle, decision_id, received=received)
            )
        except Exception as exc:
            _log.error("card webhook failed (%s)", type(exc).__name__)
            return Response(status_code=500)
        if outcome is None:
            return JSONResponse({"status": "duplicate"})
        return JSONResponse({"status": outcome.status})

    # Never debug: a debug page would show the secret among the frame's locals.
    return Starlette(
        debug=False, routes=[Route(WEBHOOK_PATH, receive, methods=["POST"])]
    )


def card_webhook_server(app: Any, port: int) -> uvicorn.Server:
    """Serve the card webhook on loopback only; a tunnel exposes this port alone.

    Args:
        app: The card webhook app.
        port: The loopback port.

    Returns:
        The server, not yet started.
    """
    return uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            limit_concurrency=_MAX_CONNECTIONS,
            # The tunnel relays from loopback, which uvicorn trusts by default.
            proxy_headers=False,
        )
    )
