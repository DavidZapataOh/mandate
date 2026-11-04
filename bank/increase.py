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
    DefaultHttpxClient,
    IdempotencyKeyAlreadyUsedError,
    Increase,
    InvalidOperationError,
    PermissionDeniedError,
    RateLimitError,
)
from increase.types import AccountTransfer

from bank.api import Payment, PaymentRequest, RailError, ReplayError
from bank.credentials import BANK_KEY_ENV, take_bank_key
from bank.rail import NO_TRANSFER, SANDBOX
from bank.reconcile import CANCELED, PENDING_APPROVAL, BankTransfer

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


class IncreaseRail:
    """Bank rail that moves money as Increase sandbox account transfers.

    Args:
        client: Increase client pinned to the sandbox.
        accounts: Mandate account name to Increase account id.
        two_step: When True, ``execute`` approves a transfer ``hold`` made
            under the same key instead of creating one.
    """

    def __init__(
        self, client: Increase, accounts: Mapping[str, str], two_step: bool = False
    ) -> None:
        self._client = client
        self._accounts = dict(accounts)
        self._two_step = two_step
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

    @classmethod
    def connect(cls, client: Increase, two_step: bool = False) -> "IncreaseRail":
        """Address every open Increase account by its name.

        Args:
            client: Increase client pinned to the sandbox.
            two_step: Whether ``execute`` approves held transfers.

        Returns:
            The rail.
        """
        return cls(client, _open_accounts(client), two_step=two_step)

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
            ValueError: If an account is unknown or funds are insufficient.
        """
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

        Args:
            request: The payment the key was sent for.
            action_hash: Salted hash of the action the payment settles.
            idempotency_key: Key the transfer was requested under.

        Returns:
            The payment when the bank holds a matching complete transfer;
            None when it holds no transfer under the key.

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
        if not held:
            return None
        if not isinstance(held[0], AccountTransfer):
            raise RailError("bank: outcome unknown")
        return self._paid(held[0], request, action_hash, idempotency_key)

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

        Reads only: the listing follows every page and writes nothing.

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
            return [
                _held(transfer)
                for transfer in self._client.account_transfers.list(
                    account_id=account_id,
                    created_at={"on_or_after": since},
                    limit=100,
                )
            ]
        except Exception:
            raise RailError("bank: unavailable") from None

    def transfer_by_key(self, key: str) -> BankTransfer | None:
        """Return the transfer the bank holds under an idempotency key.

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
            return _held(held[0]) if held else None
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
