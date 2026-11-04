"""Test-only rails and recorded bank answers for the verifier and the desk."""

import dataclasses
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
from increase import Increase

from bank.api import Payment, PaymentRequest, RailError
from bank.increase import sandbox_client
from bank.rail import SANDBOX
from bank.reconcile import BankTransfer

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
        found: Returned (or raised) by every ``reconcile``: True for the
            payment ``execute`` would have made, None to answer from
            ``listed`` by the key as the sandbox does (nothing, a payment for
            a complete transfer, or ``bank: not complete``).
    """

    def __init__(
        self,
        error: Exception | None = None,
        balance: int | Exception = 0,
        found: bool | None | Exception = None,
    ) -> None:
        self.error = error
        self._balance = balance
        self.found = found
        self.calls: list[tuple[PaymentRequest, str, str | None]] = []
        self.lookups: list[tuple[PaymentRequest, str, str | None]] = []
        self.provider = "increase"
        self.listed: list[BankTransfer] = []
        self.listed_error: Exception | None = None
        self.paid_id = "account_transfer_t1"

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
        if self.error is not None:
            raise self.error
        return self._payment(request, action_hash, idempotency_key)

    def reconcile(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str
    ) -> Payment | None:
        """Record the lookup, then raise, find nothing or find the payment."""
        self.lookups.append((request, action_hash, idempotency_key))
        if isinstance(self.found, Exception):
            raise self.found
        if self.found is None:
            return self._held(request, action_hash, idempotency_key)
        return self._payment(request, action_hash, idempotency_key)

    def _held(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str
    ) -> Payment | None:
        held = next(
            (t for t in self.listed if t.idempotency_key == idempotency_key), None
        )
        if held is None:
            return None
        if held.status != "complete":
            raise RailError("bank: not complete")
        paid = self._payment(request, action_hash, idempotency_key)
        return dataclasses.replace(paid, payment_id=held.transfer_id)

    def transfers(self, from_acct: str, since: str) -> list[BankTransfer]:
        """Raise the configured listing error or return ``listed``."""
        if self.listed_error is not None:
            raise self.listed_error
        return self.listed

    def transfer_by_key(self, key: str) -> BankTransfer | None:
        """Raise the configured listing error or find ``listed`` by key."""
        if self.listed_error is not None:
            raise self.listed_error
        return next((t for t in self.listed if t.idempotency_key == key), None)

    def _payment(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str | None
    ) -> Payment:
        return Payment(
            self.paid_id,
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


Answer = str | tuple[int, dict[str, Any]] | httpx.Response | Exception


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
            a whole response, or an exception to raise in place of a response.
    """

    def __init__(self, *answers: Answer) -> None:
        self._answers: Iterator[Answer] = iter(answers)
        self.requests: list[httpx.Request] = []

    def client(self, max_retries: int = 0) -> Increase:
        """Build a sandbox client whose every request this cassette answers.

        Args:
            max_retries: The SDK's automatic retries, which resend the same
                idempotency key after a lost response.
        """
        transport = httpx.MockTransport(self._answer)
        return sandbox_client(
            SENTINEL_KEY, httpx.Client(transport=transport), max_retries=max_retries
        )

    def _answer(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = next(self._answers)
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, httpx.Response):
            return answer
        headers: dict[str, str] = {}
        if isinstance(answer, str):
            saved = recorded(answer)
            status, body = saved["status"], saved["body"]
            if saved["replayed"] is not None:
                headers["idempotent-replayed"] = saved["replayed"]
        else:
            status, body = answer
        return httpx.Response(status, json=body, headers=headers)
