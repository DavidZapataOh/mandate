"""Cooperative bank-signed balance statements."""

import dataclasses
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_PREFIX = b"coop/v1:"


@dataclass(frozen=True)
class SignedState:
    """Bank-signed statement of funds with expiry."""

    subject: str
    statement: str
    balance_cents: int
    currency: str
    nonce: str
    issued_at: int
    expires_at: int
    signature: bytes

    def signable_bytes(self) -> bytes:
        """Canonical bytes covered by the signature.

        Returns:
            Version prefix plus compact JSON over the unsigned fields.
        """
        payload = {
            "subject": self.subject,
            "statement": self.statement,
            "balance_cents": self.balance_cents,
            "currency": self.currency,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return _PREFIX + raw.encode("ascii")


def sign_state(
    private_key: bytes,
    subject: str,
    statement: str,
    balance_cents: int,
    currency: str,
    nonce: str,
    issued_at: int,
    ttl_s: int = 300,
) -> SignedState:
    """Sign a funds statement with Ed25519.

    Args:
        private_key: Raw 32-byte Ed25519 private key.
        subject: Account or subject identifier.
        statement: Statement literal such as `"funds-sufficient"`.
        balance_cents: Balance in minor units, must be >= 0.
        currency: Currency code.
        nonce: Freshness nonce.
        issued_at: Unix issue time; expiry is `issued_at + ttl_s`.
        ttl_s: Time-to-live in seconds.

    Returns:
        The signed state with expiry and signature attached.

    Raises:
        ValueError: If the balance is negative or a field is empty.
    """
    if balance_cents < 0:
        raise ValueError("balance must be >= 0")
    if not subject or not statement or not currency or not nonce:
        raise ValueError("state fields must be non-empty")
    unsigned = SignedState(
        subject=subject,
        statement=statement,
        balance_cents=balance_cents,
        currency=currency,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=issued_at + ttl_s,
        signature=b"",
    )
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    return dataclasses.replace(unsigned, signature=key.sign(unsigned.signable_bytes()))


def verify_state(state: SignedState, public_key: bytes, now: int) -> tuple[bool, str]:
    """Verify signature and freshness of a signed state.

    Args:
        state: The signed state to check.
        public_key: Raw 32-byte Ed25519 public key.
        now: Current Unix time.

    Returns:
        `(True, "ok: cooperative")` when valid, else a denial reason.
    """
    key = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        key.verify(state.signature, state.signable_bytes())
    except InvalidSignature:
        return (False, "bad-signature: state signature invalid")
    if now > state.expires_at:
        return (False, "stale: state expired")
    if now < state.issued_at:
        return (False, "premature: state issued in future")
    return (True, "ok: cooperative")
