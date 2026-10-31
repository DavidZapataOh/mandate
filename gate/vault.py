"""Sealed secrets with certified-only disclosure."""

import base64
import secrets
from collections import deque
from dataclasses import dataclass

from cryptography.fernet import Fernet

from gate.certs import (
    BitstringRevocation,
    SingleUseStore,
    verify_certificate,
)

VAULT_BUDGET = 4096
AUDIT_BUDGET = 10000


@dataclass(frozen=True)
class AuditEntry:
    """One vault call; never carries secret material."""

    seq: int
    ts: int
    event: str
    name: str
    key_id: str
    result: str


class Vault:
    """Sealed secrets with certified-only disclosure."""

    def __init__(
        self, max_secrets: int = VAULT_BUDGET, max_audit: int = AUDIT_BUDGET
    ) -> None:
        self._max_secrets = max_secrets
        self._keys: dict[str, bytearray] = {}
        self._counter = 0
        self._live = self._mint_key()
        self._sealed: dict[str, tuple[str, bytearray]] = {}
        self._tombstoned: set[str] = set()
        self._audit: deque[AuditEntry] = deque(maxlen=max_audit)
        self._seq = 0
        self._dropped = 0

    @property
    def live_key_id(self) -> str:
        """Current data-key id (`k1`, `k2`, …)."""
        return self._live

    def store(self, name: str, secret: bytes, now: int) -> str:
        """Seal under the live key; returns the key id."""
        if name not in self._sealed and name not in self._tombstoned:
            if len(self._sealed) + len(self._tombstoned) >= self._max_secrets:
                raise ValueError("vault full: budget exceeded")
        key = self._keys[self._live]
        fernet = Fernet(base64.urlsafe_b64encode(bytes(key)))
        self._sealed[name] = (self._live, bytearray(fernet.encrypt(secret)))
        self._tombstoned.discard(name)
        self._record(now, "stored", name, self._live, "ok: stored")
        return self._live

    def inject(
        self,
        name: str,
        token: str,
        public_key: bytes,
        now: int,
        single_use: SingleUseStore,
        revocation: BitstringRevocation,
    ) -> tuple[bytes | None, str]:
        """Plaintext only for valid certs; single denied reason."""
        valid, _ = verify_certificate(
            token, public_key, now, single_use, revocation, consume=False
        )
        if not valid:
            reason = "denied: no valid certificate"
            self._record(now, "denied", name, self._live, reason)
            return (None, reason)
        if name in self._tombstoned:
            reason = "erased: secret erased"
            self._record(now, "denied", name, self._live, reason)
            return (None, reason)
        if name not in self._sealed:
            reason = "missing: no such secret"
            self._record(now, "denied", name, self._live, reason)
            return (None, reason)
        key_id, sealed = self._sealed[name]
        key = self._keys[key_id]
        fernet = Fernet(base64.urlsafe_b64encode(bytes(key)))
        reason = "ok: injected"
        self._record(now, "injected", name, key_id, reason)
        return (fernet.decrypt(bytes(sealed)), reason)

    def rotate(self, now: int) -> str:
        """Fresh live key; every live record re-sealed under it."""
        new_id = self._mint_key()
        fresh = Fernet(base64.urlsafe_b64encode(bytes(self._keys[new_id])))
        for name, (key_id, sealed) in self._sealed.items():
            stale = Fernet(base64.urlsafe_b64encode(bytes(self._keys[key_id])))
            resealed = fresh.encrypt(stale.decrypt(bytes(sealed)))
            self._sealed[name] = (new_id, bytearray(resealed))
        retired = [k for k in self._keys if k != new_id]
        for key_id in retired:
            key = self._keys[key_id]
            for i in range(len(key)):
                key[i] = 0
            del self._keys[key_id]
        self._live = new_id
        self._record(now, "rotated", "", new_id, "ok: rotated")
        return new_id

    def erase(self, name: str, now: int) -> None:
        """Tombstone a name; its ciphertext is wiped, not just dropped."""
        if name not in self._sealed:
            raise ValueError("cannot erase: no such secret")
        key_id, sealed = self._sealed[name]
        for i in range(len(sealed)):
            sealed[i] = 0
        del self._sealed[name]
        self._tombstoned.add(name)
        self._record(now, "erased", name, key_id, "ok: erased")

    def audit(self) -> tuple[AuditEntry, ...]:
        """Oldest-first entries within the budget."""
        return tuple(self._audit)

    def dropped(self) -> int:
        """Audit entries evicted past the budget."""
        return self._dropped

    def _mint_key(self) -> str:
        self._counter += 1
        key_id = f"k{self._counter}"
        self._keys[key_id] = bytearray(secrets.token_bytes(32))
        return key_id

    def _record(self, ts: int, event: str, name: str, key_id: str, result: str) -> None:
        self._seq += 1
        if len(self._audit) == self._audit.maxlen:
            self._dropped += 1
        self._audit.append(
            AuditEntry(
                seq=self._seq,
                ts=ts,
                event=event,
                name=name,
                key_id=key_id,
                result=result,
            )
        )
