"""Read-only view of the transfers a bank holds, shaped for a reconciler."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class BankTransfer:
    """One transfer as the bank reports it.

    Args:
        transfer_id: The bank's identifier for the transfer.
        amount_cents: Amount in integer cents.
        status: Transfer status the bank reported.
        idempotency_key: Key the transfer was requested under, if any.
        created_at: When the bank created it, as the bank wrote it; empty for
            a ledger that has no clock.
    """

    transfer_id: str
    amount_cents: int
    status: str
    idempotency_key: str | None
    created_at: str


class TransferLedger(Protocol):
    """A bank that can list its transfers without changing anything."""

    @property
    def rail(self) -> str:
        """Label of the rail."""
        ...

    @property
    def provider(self) -> str | None:
        """Bank that holds the transfers; None for the simulated ledger."""
        ...

    def transfers(self, from_acct: str, since: str) -> list[BankTransfer]:
        """List the transfers that left an account since a time."""
        ...

    def transfer_by_key(self, key: str) -> BankTransfer | None:
        """Return the transfer held under an idempotency key, if any."""
        ...
