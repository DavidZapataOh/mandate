"""Increase sandbox rail: certified payments become account or ACH transfers."""

import argparse
import datetime
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import httpx
from increase import (
    APIConnectionError,
    APIStatusError,
    AuthenticationError,
    DefaultHttpxClient,
    IdempotencyKeyAlreadyUsedError,
    Increase,
    InvalidOperationError,
    PermissionDeniedError,
    RateLimitError,
)
from increase.types import AccountTransfer, ACHTransfer

from bank.api import Payment, PaymentRequest, RailError, ReplayError
from bank.credentials import BANK_KEY_ENV, take_bank_key
from bank.rail import NO_TRANSFER, SANDBOX
from bank.reconcile import (
    CANCELED,
    IN_FLIGHT,
    NO_MONEY,
    PENDING_APPROVAL,
    RETURNED,
    AchState,
    BankTransfer,
)

SANDBOX_URL = "https://sandbox.increase.com"
PROVIDER = "increase"
DEMO_ACCOUNTS = ("checking-881", "acme-991")
DEMO_FUND_CENTS = 1_000_000

# Increase rejects longer transfer descriptions.
_DESCRIPTION_MAX = 200
# Increase rejects longer ACH individual names.
_INDIVIDUAL_NAME_MAX = 22
_TIME = "%Y-%m-%dT%H:%M:%SZ"

# The desk holds its lock through the bank call, so each call is bounded:
# 5 s to connect, 10 s for each read or write. The SDK retries nothing by
# itself (its retries honour a Retry-After of up to 60 s); a transfer whose
# answer is lost is settled by one lookup of its idempotency key instead. A
# payment makes at most two calls, so it gives up in about half a minute.
BANK_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
BANK_RETRIES = 0


def sandbox_client(
    api_key: str,
    http_client: httpx.Client | None = None,
    max_retries: int = BANK_RETRIES,
) -> Increase:
    """Build an Increase client pinned to the sandbox host.

    The base URL is explicit because the SDK reads ``INCREASE_BASE_URL`` from the
    environment when none is given, which would send the key to another host.
    Redirects are never followed, not even on a transport passed in: a 3xx is
    no answer about the transfer, and following it could end in a 200 that is
    not one.

    Args:
        api_key: Sandbox API key.
        http_client: Optional transport, used to record answers; it is set
            not to follow redirects.
        max_retries: Automatic retries on transient failures; each resends
            the same idempotency key.
    """
    if http_client is None:
        http_client = DefaultHttpxClient(follow_redirects=False)
    else:
        http_client.follow_redirects = False
    return Increase(
        api_key=api_key,
        base_url=SANDBOX_URL,
        http_client=http_client,
        max_retries=max_retries,
        timeout=BANK_TIMEOUT,
    )


def _open_accounts(client: Increase) -> dict[str, str]:
    return {
        account.name: account.id
        for account in client.accounts.list()
        if account.status == "open"
    }


@dataclass(frozen=True)
class AchDestination:
    """Where an ACH transfer to a payee goes.

    Args:
        account_number: The payee's account number.
        routing_number: The routing number of the payee's bank.
    """

    account_number: str
    routing_number: str


class IncreaseRail:
    """Bank rail that moves money as Increase sandbox account transfers.

    On an ACH rail (``destinations`` given) each payment leaves as an ACH
    transfer to the payee's account number instead. Money counts as moved
    once the bank accepted the transfer, because the bank holds the full
    amount from then on; its later settlement or return is read by
    ``ach_state``.

    Args:
        client: Increase client pinned to the sandbox.
        accounts: Mandate account name to Increase account id.
        two_step: When True, ``execute`` approves a transfer ``hold`` made
            under the same key instead of creating one.
        destinations: Mandate payee name to its ACH destination; when given,
            ``execute`` pays by ACH.

    Raises:
        ValueError: If both ``two_step`` and ``destinations`` are given.
    """

    def __init__(
        self,
        client: Increase,
        accounts: Mapping[str, str],
        two_step: bool = False,
        destinations: Mapping[str, AchDestination] | None = None,
    ) -> None:
        if two_step and destinations is not None:
            raise ValueError("ach and two-step are exclusive")
        self._client = client
        self._accounts = dict(accounts)
        self._two_step = two_step
        self._destinations = None if destinations is None else dict(destinations)
        # Key to the held transfer id and the request it holds. Open quotes
        # do not survive a restart, so a certificate whose hold is not here
        # takes the one-step path, which the bank answers as a replay.
        self._holding: dict[str, tuple[str, PaymentRequest]] = {}

    def __repr__(self) -> str:
        return f"IncreaseRail(sandbox, accounts={sorted(self._accounts)})"

    @property
    def rail(self) -> str:
        """Label of this rail: always the sandbox."""
        return SANDBOX

    @property
    def provider(self) -> str:
        """Bank that holds the transfers: always Increase."""
        return PROVIDER

    @property
    def two_step(self) -> bool:
        """True when ``execute`` approves held transfers."""
        return self._two_step

    @property
    def ach(self) -> bool:
        """True when ``execute`` pays by ACH transfer."""
        return self._destinations is not None

    @classmethod
    def connect(
        cls, client: Increase, two_step: bool = False, ach: bool = False
    ) -> "IncreaseRail":
        """Address every open Increase account by its name.

        Args:
            client: Increase client pinned to the sandbox.
            two_step: Whether ``execute`` approves held transfers.
            ach: Whether ``execute`` pays by ACH; each open account is then
                paid at its first active account number.

        Returns:
            The rail.

        Raises:
            ValueError: If both ``two_step`` and ``ach`` are set.
        """
        accounts = _open_accounts(client)
        destinations = _active_numbers(client, accounts) if ach else None
        return cls(client, accounts, two_step=two_step, destinations=destinations)

    def holds(self, names: Sequence[str]) -> bool:
        """Tell whether the bank holds an open account for every name.

        Args:
            names: Mandate account names.

        Returns:
            True when every name is addressable.
        """
        return all(name in self._accounts for name in names)

    def account_id(self, name: str) -> str:
        """Return the Increase id of an open demo account.

        Args:
            name: Mandate account name.

        Returns:
            The bank's account id.

        Raises:
            ValueError: If the account is unknown.
        """
        if name not in self._accounts:
            raise ValueError(f"unknown account: {name}")
        return self._accounts[name]

    def destination(self, name: str) -> AchDestination:
        """Return where an ACH transfer to a payee goes.

        Args:
            name: Mandate account name of the payee.

        Returns:
            The payee's account and routing numbers.

        Raises:
            ValueError: If the payee has no ACH destination.
        """
        if self._destinations is None or name not in self._destinations:
            raise ValueError(f"unknown account: {name}")
        return self._destinations[name]

    def execute(
        self,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str | None = None,
    ) -> Payment:
        """Move the money as one transfer under the idempotency key.

        The transfer is an account transfer, or an ACH transfer on an ACH
        rail.

        The verifier spends the certificate before it calls the rail, so the
        bank can hold a transfer under this key only because this certificate
        asked for it: a replayed answer (the SDK resending after a lost
        response) is this certificate's own transfer, paid when it matches the
        request. Only a 4xx carrying a parsed error is a definite refusal. Any
        other failure, or a 2xx or 3xx that is not a transfer, is no usable
        answer, and one lookup by the key settles it.

        Args:
            request: The payment to execute.
            action_hash: Salted hash of the action the payment settles.
            idempotency_key: Key the bank deduplicates the transfer by.

        Returns:
            The payment, identified by the bank's transfer id.

        Raises:
            ReplayError: If the bank holds the key for a transfer with other
                parameters.
            RailError: If the bank failed, refused, or reports a transfer that
                differs from the request or is not complete; the message is
                the reason.
            ValueError: If the key is missing, an account is unknown or funds
                are insufficient.
        """
        if idempotency_key is None:
            raise ValueError("sandbox transfers need an idempotency key")
        if self._destinations is not None:
            return self._send_ach(request, action_hash, idempotency_key)
        # One pop, never check-then-pop: `release` runs outside the desk lock.
        entry = self._holding.pop(idempotency_key, None) if self._two_step else None
        if entry is not None:
            return self._approve(request, action_hash, idempotency_key, entry)
        answer = self._create(request, idempotency_key, require_approval=False)
        if isinstance(answer, AccountTransfer):
            return self._paid(answer, request, action_hash, idempotency_key)
        found = self.reconcile(request, action_hash, idempotency_key)
        if found is None:
            raise RailError("bank: outcome unknown")
        return found

    def hold(self, request: PaymentRequest, idempotency_key: str) -> str:
        """Hold one account transfer for approval under the certificate's key.

        The hold is the only bank write made before a certificate exists. It
        moves no money (the bank creates the transactions only on approval),
        but it holds the amount on the source account until the transfer is
        approved or canceled. Refusals map as ``execute`` maps them; no usable
        answer is settled by one lookup of the key.

        Args:
            request: The payment the certificate will authorize.
            idempotency_key: ``mandate-cert-<jti>`` for the coming certificate.

        Returns:
            The bank's id for the held transfer.

        Raises:
            ReplayError: If the bank holds the key for a transfer with other
                parameters.
            RailError: ``bank: unavailable`` or ``bank: refused`` for a
                definite refusal; ``bank: outcome unknown`` when neither the
                answer nor the lookup finds the transfer; ``bank: transfer
                differs`` or ``bank: not held for approval`` for a transfer
                the bank did not hold as asked.
            ValueError: If an account is unknown or funds are insufficient, or
                the rail pays by ACH.
        """
        if self._destinations is not None:
            raise ValueError("ach and two-step are exclusive")
        answer = self._create(request, idempotency_key, require_approval=True)
        if not isinstance(answer, AccountTransfer):
            answer = self._by_key(idempotency_key)
            if answer is None:
                raise RailError("bank: outcome unknown")
        if not self._matches(answer, request, idempotency_key):
            raise RailError("bank: transfer differs")
        if answer.status != PENDING_APPROVAL:
            raise RailError("bank: not held for approval")
        self._holding[idempotency_key] = (answer.id, request)
        return answer.id

    def release(self, idempotency_key: str, transfer_id: str | None = None) -> str:
        """Cancel the transfer held under a key if it still awaits approval.

        Release never approves and never creates: it cancels only a transfer
        in ``pending_approval``, which cannot move money, and reports any
        other status as it stands.

        Args:
            idempotency_key: Key the hold was requested under.
            transfer_id: The hold's id when the bank answered with one; the
                transfer is then read by id, never looked up by key.

        Returns:
            The transfer's final status (``canceled``, ``complete`` or
            ``pending_approval``), or ``NO_TRANSFER`` when no id is known and
            the bank lists none under the key.

        Raises:
            RailError: If the bank cannot be read, or its answers are not
                transfers (``bank: unavailable``).
        """
        if transfer_id is not None:
            # A transfer the bank answered for is read by its id: a listing
            # that omits it must never make a hold that still holds look gone.
            listed = _hold_of(self._read(transfer_id), idempotency_key, transfer_id)
        else:
            listed = self._listed_hold(idempotency_key)
            if listed is None:
                self._holding.pop(idempotency_key, None)
                return NO_TRANSFER
        if listed is None:
            raise RailError("bank: unavailable")
        transfer = listed
        if transfer.status == PENDING_APPROVAL:
            transfer_id = transfer.id
            try:
                answer: object = self._client.account_transfers.cancel(
                    transfer_id, idempotency_key=f"mandate-cancel-{transfer_id}"
                )
            except Exception:
                answer = None
            cancel = _hold_of(answer, idempotency_key, transfer_id)
            if cancel is None:
                cancel = _hold_of(self._read(transfer_id), idempotency_key, transfer_id)
                if cancel is None:
                    raise RailError("bank: unavailable")
            transfer = cancel
        if transfer.status != PENDING_APPROVAL:
            self._holding.pop(idempotency_key, None)
        return str(transfer.status)

    def _listed_hold(self, idempotency_key: str) -> AccountTransfer | None:
        """The hold listed under a key; None when the bank lists none.

        Raises:
            RailError: If the listing cannot be read, or what it lists is not
                this key's hold in a known status (``bank: unavailable``).
        """
        try:
            page = self._client.account_transfers.list(idempotency_key=idempotency_key)
            held: object = page.data
        except Exception:
            raise RailError("bank: unavailable") from None
        if not isinstance(held, list):
            raise RailError("bank: unavailable")
        if not held:
            return None
        # Acting on any transfer but this key's own would cancel another
        # quote's hold and report this one released while it still holds.
        entry = self._holding.get(idempotency_key)
        listed = _hold_of(held[0], idempotency_key, entry[0] if entry else None)
        if listed is None:
            raise RailError("bank: unavailable")
        return listed

    def _create(
        self, request: PaymentRequest, idempotency_key: str, require_approval: bool
    ) -> object:
        """Send one keyed create; the answer, or None when it is no answer."""
        source = self.account_id(request.from_acct)
        destination = self.account_id(request.to_acct)
        description = f"Mandate {request.ref} {idempotency_key}"[:_DESCRIPTION_MAX]
        # `from None` keeps SDK messages, which echo the request, out of
        # tracebacks shown to users.
        try:
            return self._client.account_transfers.create(
                account_id=source,
                amount=request.amount_cents,
                description=description,
                destination_account_id=destination,
                require_approval=require_approval,
                idempotency_key=idempotency_key,
            )
        except APIStatusError as exc:
            refused = self._refused(exc, request, idempotency_key)
            if refused is not None:
                raise refused from None
        except Exception:
            # No answer, or one the SDK could not read: the bank may still
            # have committed the transfer.
            return None
        return None

    def _refused(
        self, exc: APIStatusError, request: PaymentRequest, idempotency_key: str
    ) -> Exception | None:
        """The error a definite refusal of a create maps to; None otherwise."""
        if not _refusal(exc):
            return None
        if isinstance(exc, IdempotencyKeyAlreadyUsedError):
            return ReplayError(idempotency_key)
        if isinstance(exc, InvalidOperationError):
            if self.get_balance(request.from_acct) < request.amount_cents:
                return ValueError(f"insufficient funds: {request.from_acct}")
            return RailError("bank: refused")
        if isinstance(
            exc, (AuthenticationError, PermissionDeniedError, RateLimitError)
        ):
            return RailError("bank: unavailable")
        return RailError("bank: refused")

    def _approve(
        self,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str,
        entry: tuple[str, PaymentRequest],
    ) -> Payment:
        # The entry was popped before the call: whatever the answer, a second
        # confirm under this key takes the one-step path, which the bank
        # refuses as a replay.
        transfer_id, held_for = entry
        # Approving moves the money, so a certificate for any other payment
        # must never reach the bank. Nothing is sent, so the hold stays
        # pending until `release` cancels it.
        if request != held_for:
            raise RailError("bank: transfer differs")
        try:
            answer: object = self._client.account_transfers.approve(
                transfer_id, idempotency_key=f"mandate-approve-{transfer_id}"
            )
        except Exception:
            # A refusal, or no answer: the read below decides either way,
            # because the approve may have committed.
            answer = None
        if not isinstance(answer, AccountTransfer):
            answer = self._read(transfer_id)
            if answer is None:
                raise RailError("bank: outcome unknown")
        if answer.id != transfer_id:
            raise RailError("bank: transfer differs")
        return self._paid(answer, request, action_hash, idempotency_key, held=True)

    def _read(self, transfer_id: str) -> AccountTransfer | None:
        """One read of a transfer by id; None when it gives no transfer."""
        try:
            answer: object = self._client.account_transfers.retrieve(transfer_id)
        except Exception:
            return None
        return answer if isinstance(answer, AccountTransfer) else None

    def _by_key(self, idempotency_key: str) -> AccountTransfer | None:
        """The transfer listed under a key; None when none can be read."""
        try:
            held: object = self._client.account_transfers.list(
                idempotency_key=idempotency_key
            ).data
        except Exception:
            return None
        if not isinstance(held, list) or not held:
            return None
        found = held[0]
        return found if isinstance(found, AccountTransfer) else None

    def reconcile(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str
    ) -> Payment | None:
        """Look up the transfer the bank holds under an idempotency key.

        The account transfers are read first and the ACH transfers only when
        none is listed under the key, on every rail: a journal left by a run
        of the other kind is never released while its transfer exists. Off an
        ACH rail an ACH transfer under the key that moved money (or still may)
        cannot be compared with any destination, so it is ``bank: not
        complete`` and stays unsettled.

        Args:
            request: The payment the key was sent for.
            action_hash: Salted hash of the action the payment settles.
            idempotency_key: Key the transfer was requested under.

        Returns:
            The payment when the bank holds a matching complete transfer (or,
            on an ACH rail, one the bank accepted); None when it holds no
            transfer under the key, or only this key's ACH transfer that moved
            nothing (canceled or rejected, or returned off an ACH rail).

        Raises:
            RailError: ``bank: outcome unknown`` when the lookup itself gets
                no answer, or one that is not a list of transfers; ``bank: not
                complete`` or ``bank: transfer differs``
                for a transfer that cannot count as this payment.
            ValueError: If an account is unknown.
        """
        try:
            page = self._client.account_transfers.list(idempotency_key=idempotency_key)
            held: object = page.data
        except Exception:
            raise RailError("bank: outcome unknown") from None
        # Only a list read as transfers can say the bank holds none.
        if not isinstance(held, list):
            raise RailError("bank: outcome unknown")
        if held:
            if not isinstance(held[0], AccountTransfer):
                raise RailError("bank: outcome unknown")
            return self._paid(held[0], request, action_hash, idempotency_key)
        return self._reconcile_ach(request, action_hash, idempotency_key)

    def _send_ach(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str
    ) -> Payment:
        """Pay by one keyed ACH transfer; refusals and lost answers as for one."""
        destination = self.destination(request.to_acct)
        source = self.account_id(request.from_acct)
        descriptor = f"Mandate {request.ref} {idempotency_key}"[:_DESCRIPTION_MAX]
        try:
            answer: object = self._client.ach_transfers.create(
                account_id=source,
                amount=request.amount_cents,
                statement_descriptor=descriptor,
                account_number=destination.account_number,
                routing_number=destination.routing_number,
                funding="checking",
                individual_name=request.to_acct[:_INDIVIDUAL_NAME_MAX],
                require_approval=False,
                idempotency_key=idempotency_key,
            )
        except APIStatusError as exc:
            refused = self._refused(exc, request, idempotency_key)
            if refused is not None:
                raise refused from None
            answer = None
        except Exception:
            # No answer, or one the SDK could not read: the bank may still
            # have accepted the transfer.
            answer = None
        if isinstance(answer, ACHTransfer):
            return self._ach_paid(answer, request, action_hash, idempotency_key)
        found = self.reconcile(request, action_hash, idempotency_key)
        if found is None:
            raise RailError("bank: outcome unknown")
        return found

    def _reconcile_ach(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str
    ) -> Payment | None:
        """The ACH transfer under a key as this payment; None if nothing moved."""
        try:
            found = self._ach_by_key(idempotency_key)
        except TypeError:
            raise RailError("bank: outcome unknown") from None
        if found is None:
            return None
        status = getattr(found, "status", None)
        # Only this key's own transfer can say nothing moved under it.
        if getattr(found, "idempotency_key", None) != idempotency_key:
            raise RailError("bank: transfer differs")
        if status in NO_MONEY:
            return None
        if self._destinations is None:
            # The payment may still be this one; a returned one moved money
            # once, so its intent must never be freed to pay again.
            raise RailError("bank: not complete")
        return self._ach_paid(found, request, action_hash, idempotency_key)

    def _ach_by_key(self, idempotency_key: str) -> ACHTransfer | None:
        """The one ACH transfer listed under a key; None when none is.

        Raises:
            TypeError: If the listing cannot be read, is not ACH transfers,
                or lists more than one under the key.
        """
        try:
            held: object = self._client.ach_transfers.list(
                idempotency_key=idempotency_key
            ).data
        except Exception:
            raise TypeError("no listing") from None
        # The bank keeps one transfer per key; more is an answer it never gives.
        if not isinstance(held, list) or len(held) > 1:
            raise TypeError("not one listing")
        if not held:
            return None
        if not isinstance(held[0], ACHTransfer):
            raise TypeError("not an ACH transfer")
        return held[0]

    def _ach_paid(
        self,
        transfer: ACHTransfer,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str,
    ) -> Payment:
        destination = self.destination(request.to_acct)
        held = (
            transfer.amount,
            transfer.currency,
            transfer.account_id,
            transfer.account_number,
            transfer.routing_number,
            transfer.idempotency_key,
        )
        asked = (
            request.amount_cents,
            request.currency,
            self.account_id(request.from_acct),
            destination.account_number,
            destination.routing_number,
            idempotency_key,
        )
        if held != asked:
            raise RailError("bank: transfer differs")
        if transfer.status in NO_MONEY:
            raise RailError("bank: refused")
        # The bank holds the full amount from acceptance on, so an accepted
        # ACH is the payment; a return is recorded later, never undone here.
        if transfer.status not in (*IN_FLIGHT, RETURNED):
            raise RailError("bank: not complete")
        return Payment(
            payment_id=transfer.id,
            from_acct=request.from_acct,
            to_acct=request.to_acct,
            amount_cents=request.amount_cents,
            currency=request.currency,
            ref=request.ref,
            action_hash=action_hash,
            rail=SANDBOX,
            provider=PROVIDER,
            status=transfer.status,
            idempotency_key=idempotency_key,
        )

    def ach_state(self, transfer_id: str) -> AchState:
        """Read where an ACH transfer stands with one read by its id.

        Args:
            transfer_id: The bank's id for the ACH transfer.

        Returns:
            Its status, and when it settled or was returned and why.

        Raises:
            RailError: If the bank cannot be read, or its answer is not this
                ACH transfer in a readable state (``bank: unavailable``).
        """
        try:
            answer: object = self._client.ach_transfers.retrieve(transfer_id)
        except Exception:
            raise RailError("bank: unavailable") from None
        state = _ach_state(answer)
        if state.transfer_id != transfer_id:
            raise RailError("bank: unavailable")
        return state

    def _paid(
        self,
        transfer: AccountTransfer,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str,
        held: bool = False,
    ) -> Payment:
        if not self._matches(transfer, request, idempotency_key):
            raise RailError("bank: transfer differs")
        if held and transfer.status == CANCELED:
            raise RailError("bank: canceled at the bank")
        # A person's dashboard approval moved the money outside the gate, so
        # it is never this certificate's payment.
        if transfer.approval is not None and transfer.approval.approved_by is not None:
            raise RailError("bank: approved outside the gate")
        if transfer.status != "complete":
            raise RailError("bank: not complete")
        return Payment(
            payment_id=transfer.id,
            from_acct=request.from_acct,
            to_acct=request.to_acct,
            amount_cents=request.amount_cents,
            currency=request.currency,
            ref=request.ref,
            action_hash=action_hash,
            rail=SANDBOX,
            provider=PROVIDER,
            status=transfer.status,
            idempotency_key=idempotency_key,
        )

    def _matches(
        self, transfer: AccountTransfer, request: PaymentRequest, idempotency_key: str
    ) -> bool:
        # The receipt certifies what the bank holds, so it must be the request.
        held = (
            transfer.amount,
            transfer.currency,
            transfer.account_id,
            transfer.destination_account_id,
            transfer.idempotency_key,
        )
        asked = (
            request.amount_cents,
            request.currency,
            self.account_id(request.from_acct),
            self.account_id(request.to_acct),
            idempotency_key,
        )
        return held == asked

    def transfers(self, from_acct: str, since: str) -> list[BankTransfer]:
        """List the transfers that left an account since a time.

        Reads only: the listing follows every page and writes nothing. The
        ACH transfers follow the account transfers on every rail, so an ACH
        no certificate explains is named whichever mode the desk runs in.

        Args:
            from_acct: Mandate account name.
            since: ISO 8601 UTC time; transfers created at or after it count.

        Returns:
            The transfers, as the bank reports them.

        Raises:
            ValueError: If the account is unknown.
            RailError: If the bank cannot be read, or its answer is not a
                list of transfers (``bank: unavailable``).
        """
        account_id = self.account_id(from_acct)
        # Any answer that does not read as transfers (a proxy's page, an odd
        # body, a dropped connection) leaves the listing unknown.
        try:
            listed = [
                _held(transfer)
                for transfer in self._client.account_transfers.list(
                    account_id=account_id,
                    created_at={"on_or_after": since},
                    limit=100,
                )
            ]
            listed += [
                _held_ach(transfer)
                for transfer in self._client.ach_transfers.list(
                    account_id=account_id,
                    created_at={"on_or_after": since},
                    limit=100,
                )
            ]
        except Exception:
            raise RailError("bank: unavailable") from None
        return listed

    def transfer_by_key(self, key: str) -> BankTransfer | None:
        """Return the transfer the bank holds under an idempotency key.

        The ACH transfers are read when no account transfer is listed under
        the key, on every rail.

        Args:
            key: Idempotency key.

        Returns:
            The transfer, or None when the bank holds none under the key.

        Raises:
            RailError: If the bank cannot be read, or its answer is not a
                list of transfers (``bank: unavailable``).
        """
        try:
            page = self._client.account_transfers.list(idempotency_key=key)
            held: object = page.data
            if not isinstance(held, list):
                raise TypeError("not a list")
            if held:
                return _held(held[0])
            ach = self._ach_by_key(key)
            return None if ach is None else _held_ach(ach)
        except Exception:
            raise RailError("bank: unavailable") from None

    def get_balance(self, acct: str) -> int:
        """Return the available balance of an account in integer cents.

        Args:
            acct: Mandate account name.

        Returns:
            The balance Increase reports as available.

        Raises:
            ValueError: If the account is unknown.
            RailError: If the bank cannot be read (``bank: unavailable``).
        """
        account_id = self.account_id(acct)
        try:
            return self._client.accounts.balance(account_id).available_balance
        except (APIConnectionError, APIStatusError):
            raise RailError("bank: unavailable") from None


def _held(transfer: object) -> BankTransfer:
    """The bank's transfer, read field by field; TypeError when it is not one."""
    if not isinstance(transfer, AccountTransfer):
        raise TypeError("not a transfer")
    return BankTransfer(
        transfer.id,
        transfer.amount,
        transfer.status,
        transfer.idempotency_key,
        transfer.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _held_ach(transfer: object) -> BankTransfer:
    """The bank's ACH transfer, read field by field; TypeError when not one."""
    if not isinstance(transfer, ACHTransfer):
        raise TypeError("not an ACH transfer")
    return BankTransfer(
        transfer.id,
        transfer.amount,
        transfer.status,
        transfer.idempotency_key,
        _stamp(transfer.created_at),
    )


def _stamp(moment: object) -> str:
    """A bank time in UTC as ``YYYY-MM-DDTHH:MM:SSZ``; TypeError if it is none."""
    if not isinstance(moment, datetime.datetime) or moment.tzinfo is None:
        raise TypeError("not a time")
    return moment.astimezone(datetime.UTC).strftime(_TIME)


def _ach_state(transfer: object) -> AchState:
    """An ACH transfer's lifecycle; ``bank: unavailable`` when it cannot be read.

    The SDK builds a transfer from any body without validating it, so a
    return is read only from a ``returned`` transfer that carries one.
    """
    if not isinstance(transfer, ACHTransfer):
        raise RailError("bank: unavailable")
    returned = transfer.return_
    if (transfer.status == RETURNED) != (returned is not None):
        raise RailError("bank: unavailable")
    try:
        if not isinstance(transfer.id, str) or not isinstance(transfer.status, str):
            raise TypeError("not a transfer")
        settlement = transfer.settlement
        settled_at = None if settlement is None else _stamp(settlement.settled_at)
        code = reason = returned_at = None
        if returned is not None:
            code, reason = returned.raw_return_reason_code, returned.return_reason_code
            if not isinstance(code, str) or not isinstance(reason, str):
                raise TypeError("not a return")
            returned_at = _stamp(returned.created_at)
    except Exception:
        raise RailError("bank: unavailable") from None
    return AchState(transfer.id, transfer.status, settled_at, code, reason, returned_at)


_RELEASED = frozenset({PENDING_APPROVAL, CANCELED, "complete"})


def _hold_of(
    answer: object, idempotency_key: str, transfer_id: str | None
) -> AccountTransfer | None:
    """The answer when it is the hold under the key in a known status; else None.

    The SDK builds a transfer from any body without validating it, so the
    key, the id (when known) and the status are checked here.
    """
    if not isinstance(answer, AccountTransfer):
        return None
    if answer.idempotency_key != idempotency_key or answer.status not in _RELEASED:
        return None
    if transfer_id is not None and answer.id != transfer_id:
        return None
    return answer


def _active_numbers(
    client: Increase, accounts: Mapping[str, str]
) -> dict[str, AchDestination]:
    """Each open account's name to its first active account number."""
    names = {account_id: name for name, account_id in accounts.items()}
    found: dict[str, AchDestination] = {}
    for number in client.account_numbers.list(status={"in": ["active"]}):
        name = names.get(number.account_id)
        if name is None or name in found or number.status != "active":
            continue
        account_number, routing_number = number.account_number, number.routing_number
        # The SDK builds a number from any body; an empty field can never pay.
        if all(isinstance(v, str) and v for v in (account_number, routing_number)):
            found[name] = AchDestination(account_number, routing_number)
    return found


def _refusal(exc: APIStatusError) -> bool:
    """Tell whether a status error is the bank definitely refusing the call.

    Only a 4xx whose body parsed into an error says nothing was made; a 3xx,
    a 5xx or an unreadable 4xx may come from something other than the bank.
    """
    return 400 <= exc.status_code < 500 and isinstance(exc.body, Mapping)


def ensure_accounts(
    client: Increase, names: Sequence[str], fund: str, target_cents: int
) -> dict[str, str]:
    """Open the named accounts the bank lacks and top one up to a target.

    Every write carries a fixed idempotency key, so running it again opens
    nothing twice.

    Args:
        client: Increase client pinned to the sandbox.
        names: Account names that must exist.
        fund: Account whose available balance must reach the target.
        target_cents: Available balance the fund account must hold.

    Returns:
        Account name to Increase account id, for every open account.
    """
    accounts = _open_accounts(client)
    for name in names:
        if name not in accounts:
            created = client.accounts.create(
                name=name, idempotency_key=f"mandate-setup-account-{name}"
            )
            accounts[name] = created.id
    available = client.accounts.balance(accounts[fund]).available_balance
    if available < target_cents:
        number = client.account_numbers.create(
            account_id=accounts[fund],
            name=f"{fund} funding",
            idempotency_key=f"mandate-setup-number-{fund}",
        )
        # A simulated inbound ACH credit is the sandbox's way in for money.
        client.simulations.inbound_ach_transfers.create(
            account_number_id=number.id, amount=target_cents - available
        )
    return accounts


def ensure_account_number(
    client: Increase, account_id: str, name: str
) -> AchDestination:
    """Return an account's first active account number, opening one if none.

    The number is opened under a fixed idempotency key, so running it again
    opens nothing twice.

    Args:
        client: Increase client pinned to the sandbox.
        account_id: Increase id of the account an ACH transfer pays into.
        name: Mandate name of that account.

    Returns:
        The account's ACH destination.

    Raises:
        ValueError: If the bank's number cannot receive an ACH transfer.
    """
    listed = client.account_numbers.list(
        account_id=account_id, status={"in": ["active"]}
    )
    number = next(iter(listed), None)
    if number is None:
        number = client.account_numbers.create(
            account_id=account_id,
            name=f"{name} ach",
            idempotency_key=f"mandate-setup-ach-number-{name}",
        )
    account_number, routing_number = number.account_number, number.routing_number
    # The SDK builds a number from any body; an empty field can never pay.
    if not all(isinstance(v, str) and v for v in (account_number, routing_number)):
        raise ValueError(f"no ACH number for {name}")
    return AchDestination(account_number, routing_number)


def setup_cli(argv: list[str] | None = None) -> None:
    """Open and fund the demo accounts in the Increase sandbox.

    With ``--ach`` it also opens the payee's account number, so a console
    started with ``--ach`` can pay it by ACH transfer.

    Args:
        argv: Command-line arguments; ``sys.argv[1:]`` when None.
    """
    parser = argparse.ArgumentParser(
        prog="mandate-bank-setup",
        description="Open and fund the demo accounts in the Increase sandbox.",
    )
    parser.add_argument("--fund-cents", type=int, default=DEMO_FUND_CENTS)
    parser.add_argument(
        "--ach",
        action="store_true",
        help="also open an account number for the payee to receive ACH transfers",
    )
    args = parser.parse_args(argv)
    key = take_bank_key(os.environ)
    if key is None:
        sys.stderr.write(f"bank rail unavailable: set {BANK_KEY_ENV}\n")
        raise SystemExit(2)
    client = sandbox_client(key)
    payer = DEMO_ACCOUNTS[0]
    payee = DEMO_ACCOUNTS[1]
    try:
        accounts = ensure_accounts(client, DEMO_ACCOUNTS, payer, args.fund_cents)
        if args.ach:
            ensure_account_number(client, accounts[payee], payee)
    except (AuthenticationError, PermissionDeniedError):
        sys.stderr.write("bank rail unavailable: the sandbox refused the key\n")
        raise SystemExit(2) from None
    except ValueError as error:
        sys.stderr.write(f"bank rail unavailable: {error}\n")
        raise SystemExit(2) from None
    rail = IncreaseRail.connect(client)
    available = rail.get_balance(payer)
    print(f"Sandbox accounts ready: {', '.join(DEMO_ACCOUNTS)}")
    print(f"{payer} available: {available} cents")
    if args.ach:
        print(f"ACH payee ready: {payee}")
