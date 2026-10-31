"""Bank-side certificate checks over proposed payment actions."""

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from bank.api import Bank, Payment, PaymentRequest

_EVENT_TYPE = "urn:mandate:secevent:cert:v1"


@dataclass(frozen=True)
class Freshness:
    """Nonce plus unix-seconds timestamp.

    Args:
        nonce: Unique freshness nonce.
        timestamp: Unix-seconds timestamp.
    """

    nonce: str
    timestamp: int


@dataclass(frozen=True)
class ProposedAction:
    """Nine immutable proposed-action fields; validated at construction.

    Args:
        version: Format version; must be "cava/1".
        runtime: Runtime the action targets.
        executable: Executable to invoke; must be non-empty.
        operation: Operation to perform; must be non-empty.
        category: Policy category.
        targets: Action target strings.
        reversible: Whether the action is reversible.
        freshness: Nonce plus timestamp; nonce non-empty, timestamp >= 0.
        evidence_refs: Evidence references.

    Raises:
        ValueError: If any validated field is out of range.
    """

    version: str
    runtime: str
    executable: str
    operation: str
    category: str
    targets: tuple[str, ...]
    reversible: bool
    freshness: Freshness
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.version != "cava/1":
            raise ValueError(f"unsupported version: {self.version!r}")
        if not self.executable:
            raise ValueError("executable must be non-empty")
        if not self.operation:
            raise ValueError("operation must be non-empty")
        if not self.freshness.nonce:
            raise ValueError("freshness nonce must be non-empty")
        if self.freshness.timestamp < 0:
            raise ValueError("freshness timestamp must be >= 0")


def action_hash(action: ProposedAction) -> str:
    """Hex SHA-256 over the canonical JSON of the action.

    Args:
        action: The proposed action to hash.

    Returns:
        Lowercase hex digest.
    """
    payload = {
        "version": action.version,
        "runtime": action.runtime,
        "executable": action.executable,
        "operation": action.operation,
        "category": action.category,
        "targets": list(action.targets),
        "reversible": action.reversible,
        "freshness": {
            "nonce": action.freshness.nonce,
            "timestamp": action.freshness.timestamp,
        },
        "evidence_refs": list(action.evidence_refs),
    }
    raw = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class PaymentResult:
    """Outcome of verify-and-execute.

    Args:
        accepted: Whether the payment executed.
        reason: Machine-readable outcome reason.
        payment: The recorded payment, or None when denied.
    """

    accepted: bool
    reason: str
    payment: Payment | None


def _parse_payment(targets: tuple[str, ...]) -> tuple[str, int, str, str, str] | None:
    """First parseable (currency, cents, from, to, ref); None when incomplete."""
    currency = ""
    cents = 0
    from_acct = ""
    to_acct = ""
    ref = ""
    for target in targets:
        if target.startswith("amount:") and not currency:
            parts = target.split(":")
            if len(parts) != 3 or not parts[1]:
                continue
            try:
                value = int(parts[2])
            except ValueError:
                continue
            if value > 0:
                currency, cents = parts[1], value
        elif target.startswith("from:") and not from_acct:
            from_acct = target[5:]
        elif target.startswith("to:") and not to_acct:
            to_acct = target[3:]
        elif target.startswith("ref:") and not ref:
            ref = target[4:]
    if not currency or not from_acct or not to_acct or not ref:
        return None
    return (currency, cents, from_acct, to_acct, ref)


class Verifier:
    """Verifies certificates and executes the approved payment.

    Args:
        public_key: Raw 32-byte Ed25519 public key.
        max_entries: Bound on remembered certificate ids.
        bits: Size of the revocation bitstring.
    """

    def __init__(
        self, public_key: bytes, max_entries: int = 100000, bits: int = 1024
    ) -> None:
        self._public_key = public_key
        self._max_entries = max_entries
        self._bits = bits
        self._seen: dict[str, bool] = {}
        self._revoked = bytearray((bits + 7) // 8)

    def revoke(self, index: int) -> None:
        """Set the revocation bit for the index.

        Args:
            index: Bit position to set.

        Raises:
            IndexError: If the index is outside [0, bits).
        """
        if not 0 <= index < self._bits:
            raise IndexError(f"revocation index out of range: {index}")
        self._revoked[index // 8] |= 1 << (index % 8)

    def _decode(self, token: str) -> tuple[dict[str, Any] | None, str | None]:
        key = Ed25519PublicKey.from_public_bytes(self._public_key)
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

    def verify_and_execute(
        self, bank: Bank, token: str, action: ProposedAction, now: int
    ) -> PaymentResult:
        """Verify the certificate and execute the matching payment.

        Args:
            bank: Ledger to execute against.
            token: Compact JWS certificate.
            action: The proposed action to execute.
            now: Current time in unix seconds.

        Returns:
            The payment result; denied results carry a None payment.
        """
        payload, error = self._decode(token)
        if payload is None or error is not None:
            return PaymentResult(False, error or "malformed: token undecodable", None)
        try:
            exp = payload["exp"]
            iat = payload["iat"]
        except KeyError:
            return PaymentResult(False, "malformed: token undecodable", None)
        if now > exp:
            return PaymentResult(False, "stale: token expired", None)
        if now < iat:
            return PaymentResult(False, "premature: issued in future", None)
        try:
            jti = payload["jti"]
            index = payload["events"][_EVENT_TYPE]["revocation_index"]
        except (KeyError, TypeError):
            return PaymentResult(False, "malformed: token undecodable", None)
        if not isinstance(jti, str):
            return PaymentResult(False, "malformed: token undecodable", None)
        if not isinstance(index, int) or not 0 <= index < self._bits:
            return PaymentResult(
                False, "malformed: revocation index out of range", None
            )
        if self._revoked[index // 8] & (1 << (index % 8)):
            return PaymentResult(False, "revoked: bit set", None)
        if jti in self._seen:
            return PaymentResult(False, "replay: jti consumed", None)
        if len(self._seen) >= self._max_entries and self._seen:
            del self._seen[next(iter(self._seen))]
        self._seen[jti] = True
        try:
            approved = payload["events"][_EVENT_TYPE]["action_hash"]
        except (KeyError, TypeError):
            return PaymentResult(False, "malformed: token undecodable", None)
        digest = action_hash(action)
        if digest != approved:
            return PaymentResult(False, "mismatch: action hash differs", None)
        parsed = _parse_payment(action.targets)
        if parsed is None:
            return PaymentResult(False, "denied: action is not a payment", None)
        currency, cents, from_acct, to_acct, ref = parsed
        if currency != "USD":
            return PaymentResult(False, "denied: unsupported currency", None)
        try:
            payment = bank.execute(
                PaymentRequest(
                    from_acct=from_acct,
                    to_acct=to_acct,
                    amount_cents=cents,
                    currency=currency,
                    ref=ref,
                ),
                digest,
            )
        except ValueError as exc:
            message = str(exc)
            if message.startswith("unknown account"):
                return PaymentResult(False, "denied: unknown account", None)
            if message.startswith("insufficient funds"):
                return PaymentResult(False, "denied: insufficient funds", None)
            raise
        return PaymentResult(True, "ok: executed", payment)
