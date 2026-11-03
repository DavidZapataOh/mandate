"""Holder consent: signed approval of one exact payment, single use."""

import dataclasses
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from gate.cava import CavaAction
from gate.policy import money_fields

_PREFIX = b"consent/v1:"
_SIGNATURE_LEN = 64
_KEY_LEN = 32


@dataclass(frozen=True)
class Consent:
    """Holder approval of one exact payment.

    Args:
        amount_cents: Approved amount in integer cents.
        currency: Currency code of the amount.
        recipient: Approved payee account.
        reference: Approved payment reference.
        source: Approved debit account.
        nonce: Unique single-use identifier.
        expires_at: Unix second after which the consent is void.
        signature: Ed25519 signature over `consent_bytes`; empty when unsigned.
    """

    amount_cents: int
    currency: str
    recipient: str
    reference: str
    source: str
    nonce: str
    expires_at: int
    signature: bytes


def _token(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and all(0x21 <= ord(ch) <= 0x7E for ch in value)
    )


def _count(value: object, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def consent_bytes(c: Consent) -> bytes:
    """Pinned bytes a holder signs for this consent.

    Args:
        c: Consent whose fields are serialized; the signature is excluded.

    Returns:
        `consent/v1:` followed by sorted-key compact ASCII JSON.

    Raises:
        ValueError: If any field is malformed.
    """
    strings = (c.currency, c.recipient, c.reference, c.source, c.nonce)
    if (
        not all(_token(s) for s in strings)
        or not _count(c.amount_cents, 1)
        or not _count(c.expires_at, 0)
    ):
        raise ValueError("consent: malformed")
    body = {
        "amount_cents": c.amount_cents,
        "currency": c.currency,
        "expires_at": c.expires_at,
        "nonce": c.nonce,
        "recipient": c.recipient,
        "reference": c.reference,
        "source": c.source,
    }
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return _PREFIX + encoded.encode("ascii")


def sign_consent(private_key: bytes, c: Consent) -> Consent:
    """Copy of the consent carrying the holder's signature.

    Args:
        private_key: Raw Ed25519 private key of the holder.
        c: Consent to sign.

    Returns:
        The consent with a 64-byte signature.

    Raises:
        ValueError: If the consent is malformed.
    """
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(consent_bytes(c))
    return dataclasses.replace(c, signature=signature)


class ConsentLedger:
    """Bounded FIFO record of consumed consent nonces."""

    def __init__(self, max_entries: int = 100000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max_entries = max_entries
        self._used: dict[str, None] = {}

    def used(self, nonce: str) -> bool:
        """True when the nonce was consumed and not yet evicted."""
        return nonce in self._used

    def consume(self, nonce: str) -> None:
        """Record the nonce, evicting the oldest past the bound."""
        self._used[nonce] = None
        while len(self._used) > self._max_entries:
            del self._used[next(iter(self._used))]


def _verifies(c: Consent, message: bytes, holder_keys: tuple[bytes, ...]) -> bool:
    if type(c.signature) is not bytes or len(c.signature) != _SIGNATURE_LEN:
        return False
    for key in holder_keys:
        if type(key) is not bytes or len(key) != _KEY_LEN:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(c.signature, message)
        except (InvalidSignature, ValueError):
            continue
        return True
    return False


def verify_signature(c: Consent, holder_keys: tuple[bytes, ...]) -> bool:
    """True when a trusted holder key signed exactly this consent's fields.

    Args:
        c: Consent carrying the signature to verify.
        holder_keys: Raw Ed25519 public keys trusted to approve.

    Returns:
        False for a malformed consent, a bad signature, or no trusted key.
    """
    try:
        message = consent_bytes(c)
    except ValueError:
        return False
    return _verifies(c, message, holder_keys)


def _matches(c: Consent, action: CavaAction) -> bool:
    fields = money_fields(action.targets)
    return (
        fields["amount"] == [f"{c.currency}:{c.amount_cents}"]
        and fields["to"] == [c.recipient]
        and fields["ref"] == [c.reference]
        and fields["from"] == [c.source]
    )


def check_consent(
    c: Consent | None,
    holder_keys: tuple[bytes, ...],
    action: CavaAction,
    now: int,
    ledger: ConsentLedger,
) -> tuple[bool, str]:
    """Verify a consent against the canonical action without consuming it.

    Args:
        c: Presented consent, if any.
        holder_keys: Raw Ed25519 public keys trusted to approve.
        action: Canonical action about to run.
        now: Current unix time in seconds.
        ledger: Record of already consumed nonces.

    Returns:
        `(True, "ok: consent")` or `(False, reason)`.
    """
    if c is None:
        return (False, "consent: missing")
    try:
        message = consent_bytes(c)
    except ValueError:
        return (False, "consent: malformed")
    if now > c.expires_at:
        return (False, "consent: expired")
    if not _verifies(c, message, holder_keys):
        return (False, "consent: bad signature")
    if ledger.used(c.nonce):
        return (False, "consent: already used")
    if not _matches(c, action):
        return (False, "consent: action differs")
    return (True, "ok: consent")
