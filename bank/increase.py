"""Increase sandbox rail: certified payments become account transfers."""

import argparse
import os
import sys
from collections.abc import Mapping, Sequence

import httpx
from increase import (
    APIConnectionError,
    APIStatusError,
    AuthenticationError,
    IdempotencyKeyAlreadyUsedError,
    Increase,
    InternalServerError,
    InvalidOperationError,
    PermissionDeniedError,
    RateLimitError,
)
from increase.types import AccountTransfer

from bank.api import Payment, PaymentRequest, RailError, ReplayError
from bank.credentials import BANK_KEY_ENV, take_bank_key
from bank.rail import SANDBOX

SANDBOX_URL = "https://sandbox.increase.com"
PROVIDER = "increase"
DEMO_ACCOUNTS = ("checking-881", "acme-991")
DEMO_FUND_CENTS = 1_000_000

# Increase rejects longer transfer descriptions.
_DESCRIPTION_MAX = 200

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

    Args:
        api_key: Sandbox API key.
        http_client: Optional transport, used to record answers.
        max_retries: Automatic retries on transient failures; each resends
            the same idempotency key.
    """
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


class IncreaseRail:
    """Bank rail that moves money as Increase sandbox account transfers.

    Args:
        client: Increase client pinned to the sandbox.
        accounts: Mandate account name to Increase account id.
    """

    def __init__(self, client: Increase, accounts: Mapping[str, str]) -> None:
        self._client = client
        self._accounts = dict(accounts)

    def __repr__(self) -> str:
        return f"IncreaseRail(sandbox, accounts={sorted(self._accounts)})"

    @property
    def rail(self) -> str:
        """Label of this rail: always the sandbox."""
        return SANDBOX

    @classmethod
    def connect(cls, client: Increase) -> "IncreaseRail":
        """Address every open Increase account by its name.

        Args:
            client: Increase client pinned to the sandbox.

        Returns:
            The rail.
        """
        return cls(client, _open_accounts(client))

    def holds(self, names: Sequence[str]) -> bool:
        """Tell whether the bank holds an open account for every name.

        Args:
            names: Mandate account names.

        Returns:
            True when every name is addressable.
        """
        return all(name in self._accounts for name in names)

    def _id(self, acct: str) -> str:
        if acct not in self._accounts:
            raise ValueError(f"unknown account: {acct}")
        return self._accounts[acct]

    def execute(
        self,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str | None = None,
    ) -> Payment:
        """Move the money as one account transfer under the idempotency key.

        The verifier spends the certificate before it calls the rail, so the
        bank can hold a transfer under this key only because this certificate
        asked for it: a replayed answer (the SDK resending after a lost
        response) is this certificate's own transfer, paid when it matches the
        request. When no answer comes at all, one lookup by the key settles it.

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
        source = self._id(request.from_acct)
        destination = self._id(request.to_acct)
        description = f"Mandate {request.ref} {idempotency_key}"[:_DESCRIPTION_MAX]
        # `from None` keeps SDK messages, which echo the request, out of
        # tracebacks shown to users.
        try:
            transfer = self._client.account_transfers.create(
                account_id=source,
                amount=request.amount_cents,
                description=description,
                destination_account_id=destination,
                require_approval=False,
                idempotency_key=idempotency_key,
            )
        except IdempotencyKeyAlreadyUsedError:
            raise ReplayError(idempotency_key) from None
        except InvalidOperationError:
            if self.get_balance(request.from_acct) < request.amount_cents:
                raise ValueError(f"insufficient funds: {request.from_acct}") from None
            raise RailError("bank: refused") from None
        except (APIConnectionError, InternalServerError):
            transfer = None
        except (AuthenticationError, PermissionDeniedError, RateLimitError):
            raise RailError("bank: unavailable") from None
        except APIStatusError:
            raise RailError("bank: refused") from None
        if transfer is not None:
            return self._paid(transfer, request, action_hash, idempotency_key)
        found = self.reconcile(request, action_hash, idempotency_key)
        if found is None:
            raise RailError("bank: outcome unknown")
        return found

    def reconcile(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str
    ) -> Payment | None:
        """Look up the transfer the bank holds under an idempotency key.

        Args:
            request: The payment the key was sent for.
            action_hash: Salted hash of the action the payment settles.
            idempotency_key: Key the transfer was requested under.

        Returns:
            The payment when the bank holds a matching complete transfer;
            None when it holds no transfer under the key.

        Raises:
            RailError: ``bank: outcome unknown`` when the lookup itself gets
                no answer; ``bank: not complete`` or ``bank: transfer differs``
                for a transfer that cannot count as this payment.
            ValueError: If an account is unknown.
        """
        try:
            page = self._client.account_transfers.list(idempotency_key=idempotency_key)
        except (APIConnectionError, APIStatusError):
            raise RailError("bank: outcome unknown") from None
        if not page.data:
            return None
        return self._paid(page.data[0], request, action_hash, idempotency_key)

    def _paid(
        self,
        transfer: AccountTransfer,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str,
    ) -> Payment:
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
            self._id(request.from_acct),
            self._id(request.to_acct),
            idempotency_key,
        )
        if held != asked:
            raise RailError("bank: transfer differs")
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
        account_id = self._id(acct)
        try:
            return self._client.accounts.balance(account_id).available_balance
        except (APIConnectionError, APIStatusError):
            raise RailError("bank: unavailable") from None


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


def setup_cli(argv: list[str] | None = None) -> None:
    """Open and fund the demo accounts in the Increase sandbox.

    Args:
        argv: Command-line arguments; ``sys.argv[1:]`` when None.
    """
    parser = argparse.ArgumentParser(
        prog="mandate-bank-setup",
        description="Open and fund the demo accounts in the Increase sandbox.",
    )
    parser.add_argument("--fund-cents", type=int, default=DEMO_FUND_CENTS)
    args = parser.parse_args(argv)
    key = take_bank_key(os.environ)
    if key is None:
        sys.stderr.write(f"bank rail unavailable: set {BANK_KEY_ENV}\n")
        raise SystemExit(2)
    client = sandbox_client(key)
    payer = DEMO_ACCOUNTS[0]
    try:
        ensure_accounts(client, DEMO_ACCOUNTS, payer, args.fund_cents)
    except (AuthenticationError, PermissionDeniedError):
        sys.stderr.write("bank rail unavailable: the sandbox refused the key\n")
        raise SystemExit(2) from None
    rail = IncreaseRail.connect(client)
    available = rail.get_balance(payer)
    print(f"Sandbox accounts ready: {', '.join(DEMO_ACCOUNTS)}")
    print(f"{payer} available: {available} cents")
