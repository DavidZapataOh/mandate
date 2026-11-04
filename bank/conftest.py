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
from bank.rail import NO_TRANSFER, SANDBOX
from bank.reconcile import CANCELED, PENDING_APPROVAL, BankTransfer

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "increase"
SENTINEL_KEY = "sandbox_key_SENTINEL_7f3a9c"


def recorded(name: str) -> dict[str, Any]:
    """Load one recorded sandbox answer: ``status``, ``replayed`` and ``body``."""
    loaded: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text())
    return loaded


class RecordingRail:
    """Fake sandbox rail that records every call and answers as configured.

    Unlike ``IncreaseRail``, ``execute`` completes a listed pending hold under
    the key whatever the request, and creates a payment for a key it holds
    nothing under; the real rail refuses a differing request before approving
    and answers a create under a held key as a replay.

    Args:
        error: Raised by every ``execute`` after the call is recorded.
        balance: Returned (or raised) by every ``get_balance``.
        found: Returned (or raised) by every ``reconcile``: True for the
            payment ``execute`` would have made, None to answer from
            ``listed`` by the key as the sandbox does (nothing, a payment for
            a complete transfer, or ``bank: not complete``).
        two_step: Whether the desk holds each quote here before it confirms.
        hold_error: Raised by every ``hold`` after the call is recorded.
        release_error: Raised by every ``release`` after the key is recorded.
    """

    def __init__(
        self,
        error: Exception | None = None,
        balance: int | Exception = 0,
        found: bool | None | Exception = None,
        two_step: bool = False,
        hold_error: Exception | None = None,
        release_error: Exception | None = None,
    ) -> None:
        self.error = error
        self._two_step = two_step
        self.holds: list[tuple[PaymentRequest, str]] = []
        self.hold_error = hold_error
        self.releases: list[str] = []
        self.released_ids: list[str | None] = []
        self.release_error = release_error
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

    @property
    def two_step(self) -> bool:
        """Whether the desk holds each quote here before it confirms."""
        return self._two_step

    def hold(self, request: PaymentRequest, idempotency_key: str) -> str:
        """Record the call, then raise ``hold_error`` or list a pending hold."""
        self.holds.append((request, idempotency_key))
        if self.hold_error is not None:
            raise self.hold_error
        transfer_id = f"account_transfer_h{len(self.holds)}"
        self.listed.append(
            BankTransfer(
                transfer_id,
                request.amount_cents,
                PENDING_APPROVAL,
                idempotency_key,
                "",
            )
        )
        return transfer_id

    def release(self, idempotency_key: str, transfer_id: str | None = None) -> str:
        """Record the key and id, then cancel a pending hold or report its status.

        The hold is found by its key in ``listed`` either way.
        """
        self.releases.append(idempotency_key)
        self.released_ids.append(transfer_id)
        if self.release_error is not None:
            raise self.release_error
        for n, listed in enumerate(self.listed):
            if listed.idempotency_key != idempotency_key:
                continue
            if listed.status != PENDING_APPROVAL:
                return listed.status
            self.listed[n] = dataclasses.replace(listed, status=CANCELED)
            return CANCELED
        return NO_TRANSFER

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
        paid = self._payment(request, action_hash, idempotency_key)
        for n, listed in enumerate(self.listed):
            if (
                listed.idempotency_key == idempotency_key
                and listed.status == PENDING_APPROVAL
            ):
                self.listed[n] = dataclasses.replace(listed, status="complete")
                return dataclasses.replace(paid, payment_id=listed.transfer_id)
        return paid

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


DOC_EVENT: dict[str, str] = {
    "associated_object_id": "account_in71c4amph0vgo2qllky",
    "associated_object_type": "account",
    "category": "account.created",
    "created_at": "2020-01-31T23:59:59Z",
    "id": "event_001dzz0r20rzr4zrhrr1364hy80",
    "type": "event",
}


def event_body(
    n: int,
    category: str = "account_transfer.created",
    object_id: str | None = None,
    created_at: str = "2026-11-04T08:58:56Z",
) -> dict[str, Any]:
    """Build the documented List Events item as event ``n`` of ``category``.

    Args:
        n: Numbers the event id and, unless given, the object id.
        category: Event category; its prefix is the object type.
        object_id: Associated object id; defaults to one numbered by ``n``.
        created_at: Event time as the bank writes it.
    """
    object_type = category.split(".")[0]
    return dict(
        DOC_EVENT,
        id=f"sandbox_event_{n:06d}",
        category=category,
        associated_object_type=object_type,
        associated_object_id=object_id or f"sandbox_{object_type}_{n:06d}",
        created_at=created_at,
    )


def events_page(
    *events: dict[str, Any], next_cursor: str | None = "c1"
) -> tuple[int, dict[str, Any]]:
    """Answer a List Events page holding ``events`` in order."""
    return 200, {"data": list(events), "next_cursor": next_cursor}
