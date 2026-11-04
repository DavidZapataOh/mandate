"""The seam between the bank verifier and whatever moves the money."""

import re
from typing import Any, Protocol

from bank.api import Payment, PaymentRequest

SIMULATED = "simulated"
SANDBOX = "sandbox"

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

    def get_balance(self, acct: str) -> int:
        """Return the available balance of an account in integer cents.

        Args:
            acct: Account name.

        Returns:
            The balance.
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
