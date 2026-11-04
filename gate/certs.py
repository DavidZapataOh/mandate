"""RFC 8417 certificates: issue, offline verify, single-use, revocation."""

import base64
import json
import os
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from gate.policy import Verdict
from gate.sdjwt import digest, disclosure, serialize

EVENT_TYPE = "urn:mandate:secevent:cert:v1"
DEFAULT_TTL_S = 300


@dataclass(frozen=True)
class CertClaims:
    """Signed statement: what action, under which policy, for whom."""

    action_hash: str
    policy_id: str
    policy_version: int
    verdict: Verdict
    freshness_nonce: str
    issued_at: int
    expires_at: int
    scope: str
    reasoning_commitment: str
    evidence_refs: tuple[str, ...]
    revocation_index: int


class SingleUseStore:
    """Bounded FIFO consume-once registry."""

    def __init__(self, max_entries: int = 100000) -> None:
        self._max_entries = max_entries
        self._seen: dict[str, bool] = {}

    def consume(self, jti: str) -> bool:
        """True on first consume; False when already present."""
        if jti in self._seen:
            return False
        if len(self._seen) >= self._max_entries and self._seen:
            del self._seen[next(iter(self._seen))]
        self._seen[jti] = True
        return True

    def __len__(self) -> int:
        return len(self._seen)


class BitstringRevocation:
    """Fixed-size revocation bitstring."""

    def __init__(self, bits: int = 1024) -> None:
        self._bits = bits
        self._words = bytearray((bits + 7) // 8)

    def _check(self, index: int) -> None:
        if not 0 <= index < self._bits:
            raise IndexError(f"revocation index out of range: {index}")

    def revoke(self, index: int) -> None:
        """Set the bit; IndexError outside the fixed range."""
        self._check(index)
        self._words[index // 8] |= 1 << (index % 8)

    def is_revoked(self, index: int) -> bool:
        """Read the bit; IndexError outside the fixed range."""
        self._check(index)
        return bool(self._words[index // 8] & (1 << (index % 8)))


def public_key_of(private_key: bytes) -> bytes:
    """Raw 32-byte Ed25519 public key for a raw private key."""
    return (
        Ed25519PrivateKey.from_private_bytes(private_key)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def generate_keypair() -> tuple[bytes, bytes]:
    """Fresh Ed25519 (private_raw, public_raw); 32 bytes each."""
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return (raw_private, raw_public)


def _subject(claims: CertClaims) -> dict[str, Any]:
    return {
        "action_hash": claims.action_hash,
        "policy_id": claims.policy_id,
        "policy_version": claims.policy_version,
        "verdict": str(claims.verdict),
        "freshness_nonce": claims.freshness_nonce,
        "scope": claims.scope,
        "reasoning_commitment": claims.reasoning_commitment,
        "evidence_refs": list(claims.evidence_refs),
        "revocation_index": claims.revocation_index,
    }


def _payload(claims: CertClaims, jti: str, subject: dict[str, Any]) -> dict[str, Any]:
    return {
        "iss": "mandate",
        "aud": "mandate-verifiers",
        "iat": claims.issued_at,
        "exp": claims.expires_at,
        "jti": jti,
        "events": {EVENT_TYPE: subject},
    }


def issue_certificate(claims: CertClaims, private_key: bytes, jti: str) -> str:
    """Compact JWS secevent; EdDSA over the pinned claim set."""
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    payload = _payload(claims, jti, _subject(claims))
    return jwt.encode(payload, key, algorithm="EdDSA", headers={"typ": "secevent+jwt"})


def _decode(token: str, public_key: bytes) -> tuple[dict[str, Any] | None, str | None]:
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError:
        return (None, "malformed: bad public key")
    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["EdDSA"],
            options={
                "verify_signature": True,
                "verify_exp": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except jwt.InvalidSignatureError:
        return (None, "bad-signature: eddsa mismatch")
    except jwt.PyJWTError:
        return (None, "malformed: token undecodable")
    return (payload, None)


def read_claims(token: str, public_key: bytes) -> tuple[dict[str, Any] | None, str]:
    """Signature-checked certificate subject; no freshness, no consumption.

    Args:
        token: Compact JWS certificate.
        public_key: Raw Ed25519 public key of the issuer.

    Returns:
        ``(subject, "ok: decoded")`` on success, else ``(None, reason)``.
    """
    payload, error = _decode(token, public_key)
    if payload is None or error is not None:
        return (None, error or "malformed: token undecodable")
    try:
        subject = payload["events"][EVENT_TYPE]
    except (KeyError, TypeError):
        return (None, "malformed: token undecodable")
    if not isinstance(subject, dict):
        return (None, "malformed: token undecodable")
    return (subject, "ok: decoded")


def _freshness(payload: dict[str, Any], now: int) -> str | None:
    try:
        exp = payload["exp"]
        iat = payload["iat"]
    except KeyError:
        return "malformed: token undecodable"
    if now > exp:
        return "stale: token expired"
    if now < iat:
        return "premature: issued in future"
    return None


def verify_certificate(
    token: str,
    public_key: bytes,
    now: int,
    store: SingleUseStore,
    revoked: BitstringRevocation,
    consume: bool = True,
) -> tuple[bool, str]:
    """Offline verify: signature, freshness, revocation, single-use."""
    payload, error = _decode(token, public_key)
    if payload is None or error is not None:
        return (False, error or "malformed: token undecodable")
    stale = _freshness(payload, now)
    if stale is not None:
        return (False, stale)
    try:
        jti = payload["jti"]
        revocation_index = payload["events"][EVENT_TYPE]["revocation_index"]
    except (KeyError, TypeError):
        return (False, "malformed: token undecodable")
    if revoked.is_revoked(revocation_index):
        return (False, "revoked: bit set")
    if consume and not store.consume(jti):
        return (False, "replay: jti consumed")
    return (True, "ok: verified")


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_sd_jwt(
    claims: CertClaims,
    private_key: bytes,
    jti: str,
    disclosable: tuple[str, ...],
) -> tuple[str, dict[str, str]]:
    """SD-JWT with salted disclosures for the named top-level keys."""
    subject = _subject(claims)
    disclosures = {
        key: disclosure(os.urandom(16), key, subject[key]) for key in disclosable
    }
    body = {key: value for key, value in subject.items() if key not in disclosures}
    body["_sd"] = sorted(digest(d) for d in disclosures.values())
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    payload = _payload(claims, jti, body)
    token = jwt.encode(payload, key, algorithm="EdDSA", headers={"typ": "secevent+jwt"})
    return (token, disclosures)


def disclose(token: str, disclosures: dict[str, str], keys: tuple[str, ...]) -> str:
    """Compact SD-JWT with the chosen disclosures only (RFC 9901 §4)."""
    return serialize(token, [disclosures[key] for key in keys])


def verify_sd_jwt(
    sandwich: str, public_key: bytes, now: int
) -> tuple[dict[str, object], bool, str]:
    """Verify sandwich; returns (visible_claims, ok, reason)."""
    parts = sandwich.split("~")
    payload, error = _decode(parts[0], public_key)
    if payload is None or error is not None:
        return ({}, False, error or "malformed: token undecodable")
    stale = _freshness(payload, now)
    if stale is not None:
        return ({}, False, stale)
    try:
        body = payload["events"][EVENT_TYPE]
        digests = set(body["_sd"])
    except (KeyError, TypeError):
        return ({}, False, "malformed: token undecodable")
    sent = [text for text in parts[1:] if text]
    if len(set(sent)) != len(sent):
        return ({}, False, "tampered: disclosure repeated")
    visible: dict[str, object] = {
        key: value for key, value in body.items() if key != "_sd"
    }
    for text in sent:
        if digest(text) not in digests:
            return ({}, False, "tampered: disclosure digest unknown")
        try:
            salted = json.loads(_b64u_decode(text).decode("ascii"))
            _, key, value = salted
        except (ValueError, TypeError):
            return ({}, False, "tampered: disclosure digest unknown")
        visible[key] = value
    return (visible, True, "ok: verified")
