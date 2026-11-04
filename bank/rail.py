"""The seam between the bank verifier and whatever moves the money."""

import re
from typing import Any, Protocol, runtime_checkable

from bank.api import Payment, PaymentRequest
from bank.reconcile import AchState

SIMULATED = "simulated"
SANDBOX = "sandbox"
# What `release` reports when the bank holds no transfer under the key.
NO_TRANSFER = "none"

_KEY_PREFIX = "mandate-cert-"
# Printable ASCII only, and short enough that the prefixed key stays within
# the 200 characters a bank accepts as an idempotency key.
_USABLE_JTI = re.compile(r"[\x21-\x7e]{1,187}")


class BankRail(Protocol):
    """Anything that moves money for a verified certificate."""

    @property
    def rail(self) -> str:
        """Label of the rail: ``SIMULATED`` or ``SANDBOX``."""
        ...

    def execute(
        self,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str | None = None,
    ) -> Payment:
        """Move the money once per idempotency key.

        Args:
            request: The payment to execute.
            action_hash: Salted hash of the action the payment settles.
            idempotency_key: Key the bank deduplicates the payment by.

        Returns:
            The payment the bank recorded.

        Raises:
            ReplayError: If the bank already holds a payment under the key.
            RailError: If the rail failed; the message is the denial reason.
            ValueError: If an account is unknown or funds are insufficient.
        """
        ...

    def reconcile(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str
    ) -> Payment | None:
        """Look up the payment the rail holds under an idempotency key.

        Args:
            request: The payment the key was sent for.
            action_hash: Salted hash of the action the payment settles.
            idempotency_key: Key the payment was requested under.

        Returns:
            The payment when one moved under the key and matches the request;
            None when nothing moved under it.

        Raises:
            RailError: If the rail cannot tell, or holds a transfer under the
                key that cannot count as this payment.
        """
        ...

    def get_balance(self, acct: str) -> int:
        """Return the available balance of an account in integer cents.

        Args:
            acct: Account name.

        Returns:
            The balance.
        """
        ...


@runtime_checkable
class HoldingRail(Protocol):
    """A bank rail that can hold a transfer for approval before it pays."""

    @property
    def two_step(self) -> bool:
        """True when ``execute`` approves held transfers."""
        ...

    def hold(self, request: PaymentRequest, idempotency_key: str) -> str:
        """Hold a transfer for approval under the certificate's key.

        The hold is the only bank write made before a certificate exists. It
        moves no money; it holds the amount until approved or canceled.

        Args:
            request: The payment the certificate will authorize.
            idempotency_key: ``mandate-cert-<jti>`` for the coming certificate.

        Returns:
            The bank's id for the held transfer.

        Raises:
            ReplayError: If the bank holds the key for another transfer.
            RailError: If the bank failed, refused, or did not hold the
                transfer as asked; the message is the reason.
            ValueError: If an account is unknown or funds are insufficient.
        """
        ...

    def release(self, idempotency_key: str, transfer_id: str | None = None) -> str:
        """Cancel the transfer held under a key if it still awaits approval.

        Release never approves and never creates: it cancels a transfer in
        ``pending_approval`` and reports any other status as it stands.

        Args:
            idempotency_key: Key the hold was requested under.
            transfer_id: The hold's id when the bank answered with one; it is
                then read by id, so a listing that omits it cannot drop it.

        Returns:
            The transfer's final status: ``canceled``, ``complete``,
            ``pending_approval``, or ``NO_TRANSFER`` when no id is known and
            the bank holds none under the key.

        Raises:
            RailError: If the bank cannot be read (``bank: unavailable``).
        """
        ...


@runtime_checkable
class AchRail(Protocol):
    """A bank rail that can pay by ACH and read each transfer's lifecycle."""

    @property
    def ach(self) -> bool:
        """True when ``execute`` pays by ACH transfer."""
        ...

    def ach_state(self, transfer_id: str) -> AchState:
        """Read where an ACH transfer stands: accepted, settled or returned.

        Args:
            transfer_id: The bank's id for the ACH transfer.

        Returns:
            The transfer's lifecycle as the bank reports it.

        Raises:
            RailError: If the bank cannot be read, or its answer is not this
                ACH transfer (``bank: unavailable``).
        """
        ...


def idempotency_key(jti: str) -> str:
    """Derive the bank idempotency key from a certificate id.

    Args:
        jti: The certificate's id.

    Returns:
        ``mandate-cert-<jti>``.

    Raises:
        ValueError: If the jti is not 1-187 printable ASCII characters.
    """
    if _USABLE_JTI.fullmatch(jti) is None:
        raise ValueError("jti unusable as idempotency key")
    return _KEY_PREFIX + jti


def bank_view(payment: Payment | None) -> dict[str, Any] | None:
    """Describe which rail moved a payment and under which transfer.

    Args:
        payment: The executed payment, or None when no rail ran.

    Returns:
        The rail, provider, transfer id, status and idempotency key, or None.
    """
    if payment is None:
        return None
    return {
        "rail": payment.rail,
        "provider": payment.provider,
        "transfer_id": payment.payment_id,
        "status": payment.status,
        "idempotency_key": payment.idempotency_key,
    }
