"""Bank-side certificate checks over proposed payment actions."""

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from bank.api import Payment, PaymentRequest, RailError, ReplayError
from bank.rail import BankRail, idempotency_key

if TYPE_CHECKING:
    # The bank runs apart from the gate; it only needs the store's shape.
    from gate.state import StateStore

_EVENT_TYPE = "urn:mandate:secevent:cert:v1"
_SALT_LEN = 32


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


def action_commitment(action: ProposedAction, salt: bytes) -> str:
    """Hex HMAC-SHA256 over the canonical JSON of the action, keyed by the salt.

    Args:
        action: The proposed action to commit to.
        salt: Exactly 32 random bytes, as type bytes.

    Returns:
        Lowercase hex digest.

    Raises:
        ValueError: If the salt is not 32 bytes.
    """
    if type(salt) is not bytes or len(salt) != _SALT_LEN:
        raise ValueError("action salt must be 32 bytes")
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
    return hmac.new(salt, raw, hashlib.sha256).hexdigest()


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


_PAYMENT_PREFIXES = ("amount:", "from:", "to:", "ref:")


def _ambiguous(targets: tuple[str, ...]) -> bool:
    """True when any payment field appears more than once.

    The bank never picks one copy: the gate may have checked another.
    """
    return any(
        sum(1 for t in targets if t.startswith(prefix)) > 1
        for prefix in _PAYMENT_PREFIXES
    )


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
        max_entries: Bound on remembered certificate ids in memory; with a
            store, ids are kept until the store prunes them after `exp`.
        bits: Size of the revocation bitstring.
        state: Durable store for spent certificate ids and revocations; None
            keeps both in memory.

    Raises:
        IndexError: If a stored revocation index is outside [0, bits).
    """

    def __init__(
        self,
        public_key: bytes,
        max_entries: int = 100000,
        bits: int = 1024,
        state: "StateStore | None" = None,
    ) -> None:
        self._public_key = public_key
        self._max_entries = max_entries
        self._bits = bits
        self._state = state
        self._seen: dict[str, bool] = {}
        self._revoked = bytearray((bits + 7) // 8)
        if state is not None:
            for index in state.revoked():
                self._set_bit(index)

    def revoke(self, index: int) -> None:
        """Set the revocation bit for the index.

        Args:
            index: Bit position to set.

        Raises:
            IndexError: If the index is outside [0, bits).
        """
        self._set_bit(index)
        if self._state is not None:
            self._state.revoke(index)

    def _set_bit(self, index: int) -> None:
        if not 0 <= index < self._bits:
            raise IndexError(f"revocation index out of range: {index}")
        self._revoked[index // 8] |= 1 << (index % 8)

    def _spend(self, jti: str, exp: int) -> bool:
        """Spend the certificate id; with a store it is on disk before the rail."""
        if self._state is not None:
            return self._state.consume("jti", jti, exp)
        if jti in self._seen:
            return False
        if len(self._seen) >= self._max_entries and self._seen:
            del self._seen[next(iter(self._seen))]
        self._seen[jti] = True
        return True

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
        self,
        bank: BankRail,
        token: str,
        action: ProposedAction,
        now: int,
        salt: bytes,
    ) -> PaymentResult:
        """Verify the certificate and execute the matching payment.

        Args:
            bank: Rail that moves the money, called at most once, last, under
                the key derived from the certificate id.
            token: Compact JWS certificate.
            action: The proposed action to execute.
            now: Current time in unix seconds.
            salt: The action salt the gate drew; the certificate binds the
                action only through it.

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
        try:
            key = idempotency_key(jti)
        except ValueError:
            return PaymentResult(False, "malformed: token undecodable", None)
        if not isinstance(index, int) or not 0 <= index < self._bits:
            return PaymentResult(
                False, "malformed: revocation index out of range", None
            )
        if self._revoked[index // 8] & (1 << (index % 8)):
            return PaymentResult(False, "revoked: bit set", None)
        if not self._spend(jti, exp):
            return PaymentResult(False, "replay: jti consumed", None)
        try:
            approved = payload["events"][_EVENT_TYPE]["action_hash"]
        except (KeyError, TypeError):
            return PaymentResult(False, "malformed: token undecodable", None)
        try:
            digest = action_commitment(action, salt)
        except ValueError:
            return PaymentResult(False, "malformed: action salt", None)
        if not isinstance(approved, str) or not hmac.compare_digest(digest, approved):
            return PaymentResult(False, "mismatch: action hash differs", None)
        if _ambiguous(action.targets):
            return PaymentResult(False, "denied: ambiguous payment fields", None)
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
                key,
            )
        except ReplayError:
            return PaymentResult(False, "replay: bank idempotency key", None)
        except RailError as exc:
            return PaymentResult(False, str(exc), None)
        except ValueError as exc:
            message = str(exc)
            if message.startswith("unknown account"):
                return PaymentResult(False, "denied: unknown account", None)
            if message.startswith("insufficient funds"):
                return PaymentResult(False, "denied: insufficient funds", None)
            raise
        return PaymentResult(True, "ok: executed", payment)
