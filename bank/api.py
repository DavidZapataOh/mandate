"""Simulated bank ledger with integer-cents payments, in memory or durable."""

import dataclasses
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gate.state import StateStore

# gate.state.NEVER_EXPIRES: the bank never imports gate at run time.
_NEVER_EXPIRES = 2**62


class ReplayError(Exception):
    """The bank already holds a payment under this idempotency key."""


class RailError(Exception):
    """The bank rail failed; the message is the pinned denial reason."""


@dataclass(frozen=True)
class PaymentRequest:
    """A request to move funds between two accounts.

    Args:
        from_acct: Source account name.
        to_acct: Destination account name.
        amount_cents: Amount in integer cents; must be positive.
        currency: Currency code.
        ref: Caller-supplied reference.

    Raises:
        ValueError: If the amount is not positive or any text field is empty.
    """

    from_acct: str
    to_acct: str
    amount_cents: int
    currency: str
    ref: str

    def __post_init__(self) -> None:
        if self.amount_cents <= 0:
            raise ValueError("amount must be positive")
        fields = (self.from_acct, self.to_acct, self.currency, self.ref)
        if any(not field for field in fields):
            raise ValueError("payment fields must be non-empty")


@dataclass(frozen=True)
class Payment:
    """A recorded payment.

    Args:
        payment_id: Ledger-assigned identifier.
        from_acct: Source account name.
        to_acct: Destination account name.
        amount_cents: Amount in integer cents.
        currency: Currency code.
        ref: Caller-supplied reference.
        action_hash: Hash of the authorized action this payment settles.
        rail: Label of the rail that moved the money.
        provider: Bank that holds the transfer; None for the simulated ledger.
        status: Transfer status the rail reported.
        idempotency_key: Key the payment was requested under, if any.
    """

    payment_id: str
    from_acct: str
    to_acct: str
    amount_cents: int
    currency: str
    ref: str
    action_hash: str
    rail: str = "simulated"
    provider: str | None = None
    status: str = "complete"
    idempotency_key: str | None = None


class Bank:
    """Ledger holding account balances and recorded payments.

    Args:
        initial: Mapping of account name to opening balance in integer cents.
        state: Durable store the ledger loads from and writes through to;
            ``initial`` is used only while it holds no balances. None keeps
            the ledger in memory.

    Raises:
        ValueError: If any opening balance is negative.
    """

    def __init__(
        self, initial: dict[str, int], state: "StateStore | None" = None
    ) -> None:
        for balance in initial.values():
            if balance < 0:
                raise ValueError("initial balance must be >= 0")
        self._state = state
        self._balances = dict(initial)
        self._payments: dict[str, Payment] = {}
        self._keys: dict[str, Payment] = {}
        if state is not None:
            self._load(state)
        self._seq = len(self._payments)

    def _load(self, state: "StateStore") -> None:
        stored = state.records("balance")
        if stored:
            self._balances = {acct: int(cents) for acct, cents in stored}
        else:
            with state.transaction():
                for acct, cents in self._balances.items():
                    state.put_record("balance", acct, str(cents))
        for payment_id, value in state.records("payment"):
            payment = Payment(**json.loads(value))
            self._payments[payment_id] = payment
            if payment.idempotency_key is not None:
                self._keys[payment.idempotency_key] = payment

    @property
    def rail(self) -> str:
        """Label of this rail: the in-memory ledger is always simulated."""
        return "simulated"

    def execute(
        self,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str | None = None,
    ) -> Payment:
        """Execute a payment, debiting the source and crediting the destination.

        Args:
            request: The payment to execute.
            action_hash: Hash of the authorized action this payment settles.
            idempotency_key: Key that makes the payment move at most once;
                None leaves the call unkeyed.

        Returns:
            The recorded payment.

        Raises:
            ReplayError: If a payment already moved under the key.
            ValueError: If either account is unknown or funds are insufficient.
        """
        if idempotency_key is not None and idempotency_key in self._keys:
            raise ReplayError(idempotency_key)
        if request.from_acct not in self._balances:
            raise ValueError(f"unknown account: {request.from_acct}")
        if request.to_acct not in self._balances:
            raise ValueError(f"unknown account: {request.to_acct}")
        if self._balances[request.from_acct] < request.amount_cents:
            raise ValueError(f"insufficient funds: {request.from_acct}")
        payment = Payment(
            payment_id=f"pay:{self._seq + 1:06d}",
            from_acct=request.from_acct,
            to_acct=request.to_acct,
            amount_cents=request.amount_cents,
            currency=request.currency,
            ref=request.ref,
            action_hash=action_hash,
            idempotency_key=idempotency_key,
        )
        if self._state is not None:
            self._write(self._state, request, payment)
        self._seq += 1
        if idempotency_key is not None:
            self._keys[idempotency_key] = payment
        self._balances[request.from_acct] -= request.amount_cents
        self._balances[request.to_acct] += request.amount_cents
        self._payments[payment.payment_id] = payment
        return payment

    def _write(
        self, state: "StateStore", request: PaymentRequest, payment: Payment
    ) -> None:
        """Commit the key, both balances and the payment together, or none."""
        cents = request.amount_cents
        with state.transaction():
            key = payment.idempotency_key
            if key is not None and not state.consume("idem", key, _NEVER_EXPIRES):
                raise ReplayError(key)
            # One dict, so paying an account to itself nets out as in memory.
            moved = {a: self._balances[a] for a in (request.from_acct, request.to_acct)}
            moved[request.from_acct] -= cents
            moved[request.to_acct] += cents
            for acct, balance in moved.items():
                state.put_record("balance", acct, str(balance))
            state.put_record(
                "payment",
                payment.payment_id,
                json.dumps(dataclasses.asdict(payment), sort_keys=True),
            )

    def reconcile(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str
    ) -> Payment | None:
        """Return the payment that moved under an idempotency key, if any.

        Args:
            request: The payment the key was sent for.
            action_hash: Salted hash of the action the payment settles.
            idempotency_key: Key the payment was requested under.

        Returns:
            The recorded payment, or None when nothing moved under the key.
        """
        return self._keys.get(idempotency_key)

    def get_balance(self, acct: str) -> int:
        """Return the balance of an account in integer cents.

        Args:
            acct: Account name.

        Returns:
            The current balance.

        Raises:
            ValueError: If the account is unknown.
        """
        if acct not in self._balances:
            raise ValueError(f"unknown account: {acct}")
        return self._balances[acct]

    def get_payment(self, payment_id: str) -> Payment:
        """Return a recorded payment by id.

        Args:
            payment_id: Ledger-assigned payment identifier.

        Returns:
            The recorded payment.

        Raises:
            ValueError: If the payment id is unknown.
        """
        if payment_id not in self._payments:
            raise ValueError(f"unknown payment: {payment_id}")
        return self._payments[payment_id]

    def accounts(self) -> tuple[str, ...]:
        """Return account names in sorted order.

        Returns:
            Sorted account names.
        """
        return tuple(sorted(self._balances))
