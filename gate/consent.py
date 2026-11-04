"""Holder consent: signed approval of one exact payment, single use."""

import base64
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
from gate.state import NEVER_EXPIRES, StateStore

_PREFIX = b"consent/v1:"
_KEY_PREFIX = b"consent-key/v1:"
_SIGNATURE_LEN = 64
_KEY_LEN = 32
_NONCE_KIND = "consent"
_KEY_KIND = "consent-key"


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
        signature: Ed25519 signature over consent_bytes by consent_key; empty when
            unsigned.
        consent_key: One-time Ed25519 public key drawn for this consent alone;
            empty when unsigned.
        key_signature: The holder key's signature over key_bytes, which
            certifies consent_key for this consent's nonce; empty when unsigned.
    """

    amount_cents: int
    currency: str
    recipient: str
    reference: str
    source: str
    nonce: str
    expires_at: int
    signature: bytes
    consent_key: bytes = b""
    key_signature: bytes = b""


@dataclass(frozen=True)
class HolderApproval:
    """What the holder's device returns for one quote.

    Args:
        signature: One-time key's Ed25519 signature over `consent_bytes`.
        consent_key: Raw 32-byte one-time Ed25519 public key.
        key_signature: Holder key's signature over `key_bytes(consent_key, nonce)`.
    """

    signature: bytes
    consent_key: bytes
    key_signature: bytes


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


def key_bytes(consent_key: bytes, nonce: str) -> bytes:
    """Pinned bytes the holder key signs to certify a one-time consent key.

    Only the nonce ties the key to its consent, so a disclosed certificate
    confirms nothing about the payment fields.

    Args:
        consent_key: Raw 32-byte one-time Ed25519 public key.
        nonce: Nonce of the consent the key may sign.

    Returns:
        `consent-key/v1:` followed by sorted-key compact ASCII JSON.

    Raises:
        ValueError: If the key or the nonce is malformed.
    """
    if (
        type(consent_key) is not bytes
        or len(consent_key) != _KEY_LEN
        or not _token(nonce)
    ):
        raise ValueError("consent: malformed")
    key = base64.b64encode(consent_key).decode("ascii")
    body = {"consent_key": key, "nonce": nonce}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return _KEY_PREFIX + encoded.encode("ascii")


def sign_approval(
    private_key: bytes, c: Consent, one_time_seed: bytes | None = None
) -> HolderApproval:
    """Approve a consent with a fresh one-time key the holder key certifies.

    Args:
        private_key: Raw Ed25519 private key of the holder.
        c: Consent to approve.
        one_time_seed: Raw seed of the one-time key; None draws a fresh one.

    Returns:
        The one-time signature, the one-time public key and its certificate.

    Raises:
        ValueError: If the consent is malformed.
    """
    one_time = (
        Ed25519PrivateKey.generate()
        if one_time_seed is None
        else Ed25519PrivateKey.from_private_bytes(one_time_seed)
    )
    consent_key = one_time.public_key().public_bytes_raw()
    holder = Ed25519PrivateKey.from_private_bytes(private_key)
    return HolderApproval(
        signature=one_time.sign(consent_bytes(c)),
        consent_key=consent_key,
        key_signature=holder.sign(key_bytes(consent_key, c.nonce)),
    )


def with_approval(c: Consent, approval: HolderApproval) -> Consent:
    """Copy of the consent carrying the holder's approval.

    Args:
        c: Consent the approval was made for.
        approval: Approval returned by the holder's device.

    Returns:
        The consent with signature, consent key and key signature set.
    """
    return dataclasses.replace(
        c,
        signature=approval.signature,
        consent_key=approval.consent_key,
        key_signature=approval.key_signature,
    )


def sign_consent(
    private_key: bytes, c: Consent, one_time_seed: bytes | None = None
) -> Consent:
    """Copy of the consent approved through a one-time key the holder certifies.

    Args:
        private_key: Raw Ed25519 private key of the holder.
        c: Consent to sign.
        one_time_seed: Raw seed of the one-time key; None draws a fresh one.

    Returns:
        The consent with signature, consent key and key signature set.

    Raises:
        ValueError: If the consent is malformed.
    """
    return with_approval(c, sign_approval(private_key, c, one_time_seed))


class ConsentLedger:
    """Record of consumed consent nonces and one-time keys.

    In memory the record is a bounded FIFO. With a store it lives in the
    store's `used` table instead, where every row is kept until the store
    prunes it after the consent expired, so a restart forgets nothing a
    consent could still be presented for.

    Args:
        max_entries: Bound on the in-memory record; unused with a store.
        state: Durable store to write through to; None keeps it in memory.

    Raises:
        ValueError: If max_entries is below 1.
    """

    def __init__(
        self, max_entries: int = 100000, state: StateStore | None = None
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max_entries = max_entries
        self._state = state
        self._used: dict[str, None] = {}
        self._keys: dict[bytes, None] = {}

    def used(self, nonce: str) -> bool:
        """True when the nonce was consumed and not yet evicted or pruned."""
        if self._state is not None:
            return self._state.used(_NONCE_KIND, nonce)
        return nonce in self._used

    def consume(self, nonce: str, expires_at: int = NEVER_EXPIRES) -> None:
        """Record the nonce; with a store it is on disk when this returns.

        Args:
            nonce: The consent's nonce.
            expires_at: When the consent expires; the store may forget the
                nonce after it.
        """
        if self._state is not None:
            self._state.consume(_NONCE_KIND, nonce, expires_at)
            return
        self._used[nonce] = None
        while len(self._used) > self._max_entries:
            del self._used[next(iter(self._used))]

    def key_used(self, consent_key: bytes) -> bool:
        """True when the one-time key was consumed and not yet evicted or pruned."""
        if self._state is not None:
            return self._state.used(_KEY_KIND, consent_key.hex())
        return consent_key in self._keys

    def consume_key(self, consent_key: bytes, expires_at: int = NEVER_EXPIRES) -> None:
        """Record the one-time key; with a store it is on disk when this returns.

        Args:
            consent_key: The consent's raw one-time public key.
            expires_at: When the consent expires; the store may forget the
                key after it.
        """
        if self._state is not None:
            self._state.consume(_KEY_KIND, consent_key.hex(), expires_at)
            return
        self._keys[consent_key] = None
        while len(self._keys) > self._max_entries:
            del self._keys[next(iter(self._keys))]

    def spend(
        self, nonce: str, consent_key: bytes, expires_at: int = NEVER_EXPIRES
    ) -> None:
        """Record a consent's nonce and one-time key together.

        With a store both land in one transaction, so a crash between them
        leaves neither spent rather than a nonce whose key could be certified
        again.

        Args:
            nonce: The consent's nonce.
            consent_key: The consent's raw one-time public key.
            expires_at: When the consent expires.
        """
        if self._state is None:
            self.consume(nonce, expires_at)
            self.consume_key(consent_key, expires_at)
            return
        with self._state.transaction():
            self.consume(nonce, expires_at)
            self.consume_key(consent_key, expires_at)


def _sized(value: object, size: int) -> bool:
    return type(value) is bytes and len(value) == size


def _signed(key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _certifier(
    c: Consent, message: bytes, holder_keys: tuple[bytes, ...]
) -> bytes | None:
    if not (
        _sized(c.signature, _SIGNATURE_LEN)
        and _sized(c.consent_key, _KEY_LEN)
        and _sized(c.key_signature, _SIGNATURE_LEN)
        and _signed(c.consent_key, c.signature, message)
    ):
        return None
    certified = key_bytes(c.consent_key, c.nonce)
    return next(
        (
            key
            for key in holder_keys
            if _sized(key, _KEY_LEN) and _signed(key, c.key_signature, certified)
        ),
        None,
    )


def _verifies(c: Consent, message: bytes, holder_keys: tuple[bytes, ...]) -> bool:
    return _certifier(c, message, holder_keys) is not None


def certifying_key(c: Consent, holder_keys: tuple[bytes, ...]) -> bytes | None:
    """The holder key that certified the one-time key that signed this consent.

    Args:
        c: Consent carrying the one-time signature and its certificate.
        holder_keys: Raw Ed25519 public keys to try, in order.

    Returns:
        The first key whose certificate verifies; None for a malformed
        consent or a chain no key completes.
    """
    try:
        message = consent_bytes(c)
    except ValueError:
        return None
    return _certifier(c, message, holder_keys)


def verify_signature(c: Consent, holder_keys: tuple[bytes, ...]) -> bool:
    """True when a trusted holder key certified the key that signed this consent.

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
        ledger: Record of already consumed nonces and one-time keys.

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
    # A key seen before, or the holder's own, would link this receipt to others.
    if ledger.key_used(c.consent_key) or c.consent_key in holder_keys:
        return (False, "consent: key reused")
    if not _matches(c, action):
        return (False, "consent: action differs")
    return (True, "ok: consent")
