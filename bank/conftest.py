"""Test-only rails and recorded bank answers for the verifier and the desk."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
from increase import Increase

from bank.api import Payment, PaymentRequest
from bank.increase import sandbox_client
from bank.rail import SANDBOX

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "increase"
SENTINEL_KEY = "sandbox_key_SENTINEL_7f3a9c"


def recorded(name: str) -> dict[str, Any]:
    """Load one recorded sandbox answer: ``status``, ``replayed`` and ``body``."""
    loaded: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text())
    return loaded


class RecordingRail:
    """Fake sandbox rail that records every call and answers as configured.

    Args:
        error: Raised by every ``execute`` after the call is recorded.
        balance: Returned (or raised) by every ``get_balance``.
    """

    def __init__(
        self, error: Exception | None = None, balance: int | Exception = 0
    ) -> None:
        self._error = error
        self._balance = balance
        self.calls: list[tuple[PaymentRequest, str, str | None]] = []

    @property
    def rail(self) -> str:
        """Always the sandbox label."""
        return SANDBOX

    def execute(
        self,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str | None = None,
    ) -> Payment:
        """Record the call, then raise the configured error or pay."""
        self.calls.append((request, action_hash, idempotency_key))
        if self._error is not None:
            raise self._error
        return Payment(
            "account_transfer_t1",
            request.from_acct,
            request.to_acct,
            request.amount_cents,
            request.currency,
            request.ref,
            action_hash,
            rail=SANDBOX,
            provider="increase",
            idempotency_key=idempotency_key,
        )

    def get_balance(self, acct: str) -> int:
        """Return or raise the configured balance."""
        if isinstance(self._balance, Exception):
            raise self._balance
        return self._balance


Answer = str | tuple[int, dict[str, Any]] | Exception


def named_accounts(*names: str) -> tuple[int, dict[str, Any]]:
    """Answer an account list holding one open account per name.

    Each is the recorded account renamed, with the id ``account_<name>``.
    """
    account = recorded("account")["body"]
    data = [dict(account, name=name, id=f"account_{name}") for name in names]
    return 200, {"data": data, "next_cursor": None}


class Cassette:
    """Fake bank transport that answers each request with the next answer.

    Args:
        answers: In order, a recorded fixture name, a ``(status, body)`` pair,
            or an exception to raise in place of a response.
    """

    def __init__(self, *answers: Answer) -> None:
        self._answers: Iterator[Answer] = iter(answers)
        self.requests: list[httpx.Request] = []

    def client(self) -> Increase:
        """Build a sandbox client whose every request this cassette answers."""
        transport = httpx.MockTransport(self._answer)
        return sandbox_client(
            SENTINEL_KEY, httpx.Client(transport=transport), max_retries=0
        )

    def _answer(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = next(self._answers)
        if isinstance(answer, Exception):
            raise answer
        headers: dict[str, str] = {}
        if isinstance(answer, str):
            saved = recorded(answer)
            status, body = saved["status"], saved["body"]
            if saved["replayed"] is not None:
                headers["idempotent-replayed"] = saved["replayed"]
        else:
            status, body = answer
        return httpx.Response(status, json=body, headers=headers)
