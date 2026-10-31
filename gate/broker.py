"""Parent-to-child delegation links with strict-subset attenuation."""

import json
from dataclasses import dataclass, replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from gate.certs import BitstringRevocation

PREFIX = b"delegate/v1:"


@dataclass(frozen=True)
class Scope:
    """Frozen atom-set plus integer spend cap."""

    atoms: tuple[str, ...]
    max_spend_cents: int


@dataclass(frozen=True)
class Delegation:
    """One signed parent-to-child attenuation link."""

    v: int
    child_pub: bytes
    scope: Scope
    expires_at: int
    parent_ref: str
    revocation_index: int
    signature: bytes

    def signable_bytes(self) -> bytes:
        """Canonical bytes the parent signs (pinned format)."""
        body = {
            "v": self.v,
            "child_pub": self.child_pub.hex(),
            "scope": {
                "atoms": sorted(self.scope.atoms),
                "max_spend_cents": self.scope.max_spend_cents,
            },
            "expires_at": self.expires_at,
            "parent_ref": self.parent_ref,
            "revocation_index": self.revocation_index,
        }
        text = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return PREFIX + text.encode("ascii")


def mint(
    parent_priv: bytes,
    parent_pub: bytes,
    child_pub: bytes,
    scope: Scope,
    parent_scope: Scope,
    expires_at: int,
    revocation_index: int,
) -> Delegation:
    """Mint a child link; raises unless scope is strictly inside parent."""
    atoms = set(scope.atoms)
    parent_atoms = set(parent_scope.atoms)
    subset = atoms <= parent_atoms
    cap_within = scope.max_spend_cents <= parent_scope.max_spend_cents
    narrowed = atoms < parent_atoms
    lowered = scope.max_spend_cents < parent_scope.max_spend_cents
    if not (subset and cap_within and (narrowed or lowered)):
        raise ValueError("cannot delegate: scope exceeds parent")
    unsigned = Delegation(
        v=1,
        child_pub=child_pub,
        scope=scope,
        expires_at=expires_at,
        parent_ref=parent_pub.hex(),
        revocation_index=revocation_index,
        signature=b"",
    )
    signature = Ed25519PrivateKey.from_private_bytes(parent_priv).sign(
        unsigned.signable_bytes()
    )
    return replace(unsigned, signature=signature)


def _strictly_inside(scope: Scope, parent_scope: Scope) -> bool:
    atoms = set(scope.atoms)
    parent_atoms = set(parent_scope.atoms)
    subset = atoms <= parent_atoms
    cap_within = scope.max_spend_cents <= parent_scope.max_spend_cents
    narrowed = atoms < parent_atoms
    lowered = scope.max_spend_cents < parent_scope.max_spend_cents
    return subset and cap_within and (narrowed or lowered)


def verify_chain(
    chain: tuple[Delegation, ...],
    root_pub: bytes,
    root_scope: Scope,
    now: int,
    revoked: BitstringRevocation,
) -> tuple[bool, str]:
    """Walk root to leaf; first failing arm denies with its reason."""
    if not chain:
        return (False, "empty: chain has no links")
    if chain[0].parent_ref != root_pub.hex():
        return (False, "anchor: first link not issued by root")
    parent_pub = root_pub
    parent_scope = root_scope
    for index, link in enumerate(chain):
        if index > 0 and link.parent_ref != parent_pub.hex():
            return (False, "broken: parent reference mismatch")
        if now > link.expires_at:
            return (False, "expired: delegation lapsed")
        try:
            Ed25519PublicKey.from_public_bytes(parent_pub).verify(
                link.signature, link.signable_bytes()
            )
        except (InvalidSignature, ValueError):
            return (False, "bad-signature: chain link invalid")
        if not _strictly_inside(link.scope, parent_scope):
            return (False, "scope: link exceeds parent")
        if revoked.is_revoked(link.revocation_index):
            return (False, "revoked: delegation revoked")
        parent_pub = link.child_pub
        parent_scope = link.scope
    return (True, "ok: chain valid")
