"""Read-only view of the transfers a bank holds, shaped for a reconciler."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

_KEY_PREFIX = "mandate-cert-"
# A canceled transfer moved no money, so it has nothing to explain.
CANCELED = "canceled"


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


@runtime_checkable
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


@dataclass(frozen=True)
class Reconciliation:
    """One comparison of the bank's transfers with the sealed registry.

    Args:
        rail: Label of the rail that was read.
        provider: Bank that holds the transfers; None for the simulated ledger.
        since: ISO 8601 UTC time the listing starts at (the registry's start).
        checked_at: Unix time of the check.
        transfers: Listed transfers that moved money.
        certified: Of those, the ones a certificate and a sealed entry explain.
        unbacked: Ids of the listed transfers nothing explains, in listing order.
        missing: Ids of sealed payments the bank does not list, sorted.
        resolved: ``<quote id> -> <transfer id>`` or ``<quote id> -> not paid``
            for each journaled payment settled by this check.
        pending: Quote ids whose journaled payment is still unsettled.
        paid_twice: ``<intent id> -> <payment id> + <payment id>`` for each
            intent more than one transfer paid.
        unreadable: ``<kind> <key>`` for each stored journal or receipt this
            check could not read; the rest of the check still ran.
        error: Why the bank could not be read, or None.
    """

    rail: str
    provider: str | None
    since: str
    checked_at: int
    transfers: int
    certified: int
    unbacked: tuple[str, ...]
    missing: tuple[str, ...]
    resolved: tuple[str, ...]
    pending: tuple[str, ...]
    paid_twice: tuple[str, ...]
    unreadable: tuple[str, ...]
    error: str | None

    def view(self) -> dict[str, Any]:
        """JSON-ready view with every list as a list, in field order."""
        return {
            "rail": self.rail,
            "provider": self.provider,
            "since": self.since,
            "checked_at": self.checked_at,
            "transfers": self.transfers,
            "certified": self.certified,
            "unbacked": list(self.unbacked),
            "missing": list(self.missing),
            "resolved": list(self.resolved),
            "pending": list(self.pending),
            "paid_twice": list(self.paid_twice),
            "unreadable": list(self.unreadable),
            "error": self.error,
        }


def compare(
    listed: Sequence[BankTransfer],
    sealed: Mapping[str, tuple[str, bool]],
    rail: str,
) -> tuple[int, tuple[str, ...], tuple[str, ...]]:
    """Match the bank's transfers with the sealed receipts, both ways.

    A listed transfer is certified when its idempotency key names the
    certificate of the sealed receipt for the same transfer id and that
    receipt's entry is the registry's; any other transfer that moved money is
    unbacked. A sealed payment the bank does not list, or lists as canceled,
    is missing.

    Args:
        listed: The transfers the bank lists from the desk's account.
        sealed: For each stored receipt on ``rail``, its payment id mapped to
            its certificate's jti and whether its entry is the registry's.
        rail: Label of the rail both sides belong to.

    Returns:
        The number of certified transfers, the unbacked transfer ids in listing
        order, and the missing payment ids sorted.
    """
    certified = 0
    unbacked: list[str] = []
    for transfer in listed:
        if transfer.status == CANCELED:
            continue
        found = sealed.get(transfer.transfer_id)
        if (
            found is not None
            and found[1]
            and transfer.idempotency_key == _KEY_PREFIX + found[0]
        ):
            certified += 1
        else:
            unbacked.append(transfer.transfer_id)
    held = {t.transfer_id for t in listed if t.status != CANCELED}
    missing = tuple(sorted(pid for pid in sealed if pid not in held))
    return certified, tuple(unbacked), missing
