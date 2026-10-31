import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from gate.broker import Delegation, Scope, action_within_scope, mint, verify_chain
from gate.certs import BitstringRevocation, generate_keypair


def _root_scope() -> Scope:
    return Scope(atoms=("domain:acme.com", "mcp:bank.pay"), max_spend_cents=20000)


def test_mint_strict_subset():
    parent_priv, parent_pub = generate_keypair()
    _, child_pub = generate_keypair()
    d = mint(
        parent_priv,
        parent_pub,
        child_pub,
        Scope(atoms=("mcp:bank.pay",), max_spend_cents=5000),
        _root_scope(),
        1800003600,
        3,
    )
    assert d.v == 1
    assert d.parent_ref == parent_pub.hex()
    assert d.revocation_index == 3
    assert d.signable_bytes().startswith(b"delegate/v1:")
    Ed25519PublicKey.from_public_bytes(parent_pub).verify(
        d.signature, d.signable_bytes()
    )
    same_atoms = mint(
        parent_priv,
        parent_pub,
        child_pub,
        Scope(atoms=("domain:acme.com", "mcp:bank.pay"), max_spend_cents=19999),
        _root_scope(),
        1800003600,
        3,
    )
    assert same_atoms.scope.max_spend_cents == 19999


def test_child_cannot_exceed_parent():
    parent_priv, parent_pub = generate_keypair()
    _, child_pub = generate_keypair()
    parent = _root_scope()
    with pytest.raises(ValueError, match="cannot delegate"):
        mint(parent_priv, parent_pub, child_pub, parent, parent, 1800003600, 3)
    wider = Scope(
        atoms=("domain:acme.com", "mcp:bank.pay", "domain:evil.com"),
        max_spend_cents=100,
    )
    with pytest.raises(ValueError, match="cannot delegate"):
        mint(parent_priv, parent_pub, child_pub, wider, parent, 1800003600, 3)
    richer = Scope(atoms=("mcp:bank.pay",), max_spend_cents=20001)
    with pytest.raises(ValueError, match="cannot delegate"):
        mint(parent_priv, parent_pub, child_pub, richer, parent, 1800003600, 3)


def _chain():
    root_priv, root_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    _, b_pub = generate_keypair()
    root_scope = _root_scope()
    a_scope = Scope(atoms=("mcp:bank.pay",), max_spend_cents=5000)
    b_scope = Scope(atoms=("mcp:bank.pay",), max_spend_cents=100)
    l0 = mint(root_priv, root_pub, a_pub, a_scope, root_scope, 1800003600, 3)
    l1 = mint(a_priv, a_pub, b_pub, b_scope, a_scope, 1800003600, 4)
    return (l0, l1), root_pub, root_scope


def test_chain_verifies_offline():
    chain, root_pub, root_scope = _chain()
    ok, reason = verify_chain(
        chain, root_pub, root_scope, 1800000000, BitstringRevocation()
    )
    assert (ok, reason) == (True, "ok: chain valid")


def test_tampered_link_rejected():
    chain, root_pub, root_scope = _chain()
    tampered = dataclasses.replace(chain[1], scope=_root_scope())
    ok, reason = verify_chain(
        (chain[0], tampered),
        root_pub,
        root_scope,
        1800000000,
        BitstringRevocation(),
    )
    assert (ok, reason) == (False, "bad-signature: chain link invalid")


def test_swapped_links_rejected():
    chain, root_pub, root_scope = _chain()
    ok, reason = verify_chain(
        chain[::-1], root_pub, root_scope, 1800000000, BitstringRevocation()
    )
    assert (ok, reason) == (False, "anchor: first link not issued by root")


def test_broken_parent_ref_rejected():
    chain, root_pub, root_scope = _chain()
    broken = dataclasses.replace(chain[1], parent_ref="00" * 32)
    ok, reason = verify_chain(
        (chain[0], broken),
        root_pub,
        root_scope,
        1800000000,
        BitstringRevocation(),
    )
    assert (ok, reason) == (False, "broken: parent reference mismatch")


def test_widened_link_rejected():
    root_priv, root_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    _, b_pub = generate_keypair()
    root_scope = _root_scope()
    a_scope = Scope(atoms=("mcp:bank.pay",), max_spend_cents=5000)
    l0 = mint(root_priv, root_pub, a_pub, a_scope, root_scope, 1800003600, 3)
    unsigned = Delegation(
        v=1,
        child_pub=b_pub,
        scope=_root_scope(),
        expires_at=1800003600,
        parent_ref=a_pub.hex(),
        revocation_index=4,
        signature=b"",
    )
    sig = Ed25519PrivateKey.from_private_bytes(a_priv).sign(unsigned.signable_bytes())
    wide = dataclasses.replace(unsigned, signature=sig)
    ok, reason = verify_chain(
        (l0, wide), root_pub, root_scope, 1800000000, BitstringRevocation()
    )
    assert (ok, reason) == (False, "scope: link exceeds parent")


def test_expired_rejected():
    chain, root_pub, root_scope = _chain()
    ok, reason = verify_chain(
        chain, root_pub, root_scope, 1800003601, BitstringRevocation()
    )
    assert (ok, reason) == (False, "expired: delegation lapsed")


def test_revoked_rejected():
    chain, root_pub, root_scope = _chain()
    revoked = BitstringRevocation()
    revoked.revoke(4)
    ok, reason = verify_chain(chain, root_pub, root_scope, 1800000000, revoked)
    assert (ok, reason) == (False, "revoked: delegation revoked")


def test_malformed_key_bytes_deny():
    chain, root_pub, root_scope = _chain()
    short_pub = b"\x00" * 10
    spoofed = dataclasses.replace(chain[0], parent_ref=short_pub.hex())
    ok, reason = verify_chain(
        (spoofed,), short_pub, root_scope, 1800000000, BitstringRevocation()
    )
    assert (ok, reason) == (False, "bad-signature: chain link invalid")
    bad_sig = dataclasses.replace(chain[1], signature=b"\x00" * 10)
    ok, reason = verify_chain(
        (chain[0], bad_sig), root_pub, root_scope, 1800000000, BitstringRevocation()
    )
    assert (ok, reason) == (False, "bad-signature: chain link invalid")


def test_empty_chain_rejected():
    _, root_pub, root_scope = _chain()
    assert verify_chain(
        (), root_pub, root_scope, 1800000000, BitstringRevocation()
    ) == (False, "empty: chain has no links")


def test_out_of_range_revocation_index_denied() -> None:
    root_priv, root_pub = generate_keypair()
    _, child_pub = generate_keypair()
    link = mint(
        root_priv,
        root_pub,
        child_pub,
        Scope(atoms=("mcp:bank.pay",), max_spend_cents=5000),
        _root_scope(),
        1800003600,
        5000,
    )
    ok, reason = verify_chain(
        (link,), root_pub, _root_scope(), 1800000000, BitstringRevocation()
    )
    assert (ok, reason) == (False, "malformed: revocation index out of range")


def test_narrowed_equal_cap_mints():
    parent_priv, parent_pub = generate_keypair()
    _, child_pub = generate_keypair()
    d = mint(
        parent_priv,
        parent_pub,
        child_pub,
        Scope(atoms=("mcp:bank.pay",), max_spend_cents=20000),
        _root_scope(),
        1800003600,
        5,
    )
    assert d.scope.max_spend_cents == 20000


def test_action_within_scope(sample_action):
    narrow = Scope(atoms=("mcp:bank.pay",), max_spend_cents=5000)
    ok_action = dataclasses.replace(
        sample_action, targets=("mcp:bank.pay", "amount:USD:100")
    )
    assert action_within_scope(narrow, ok_action) == (True, "ok: within scope")
    over_target = dataclasses.replace(
        sample_action,
        targets=("mcp:bank.pay", "domain:evil.com", "amount:USD:100"),
    )
    assert action_within_scope(narrow, over_target) == (
        False,
        "scope: target outside delegation",
    )
    over_spend = dataclasses.replace(
        sample_action, targets=("mcp:bank.pay", "amount:USD:6000")
    )
    assert action_within_scope(narrow, over_spend) == (
        False,
        "scope: spend exceeds delegation",
    )
    bad = dataclasses.replace(
        sample_action, targets=("mcp:bank.pay", "amount:USD:lots")
    )
    assert action_within_scope(narrow, bad) == (False, "scope: malformed amount")
