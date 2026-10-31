import dataclasses
import json

import pytest

from gate.certs import (
    BitstringRevocation,
    SingleUseStore,
    generate_keypair,
    issue_certificate,
)
from gate.vault import Vault


def _stores():
    return SingleUseStore(), BitstringRevocation()


def _token(cert_claims, private_key, jti):
    return issue_certificate(cert_claims, private_key, jti)


def test_certified_injects(keypair, cert_claims):
    priv, pub = keypair
    v = Vault()
    assert v.store("db/password", b"s3cr3t", 1800000000) == "k1"
    assert v.live_key_id == "k1"
    token = _token(cert_claims, priv, "vault-jti-1")
    secret, reason = v.inject("db/password", token, pub, 1800000100, *_stores())
    assert (secret, reason) == (b"s3cr3t", "ok: injected")
    assert v.audit()[-1].event == "injected"


def test_uncertified_gets_nothing(keypair, cert_claims):
    priv, pub = keypair
    v = Vault()
    v.store("db/password", b"s3cr3t", 1800000000)
    token = _token(cert_claims, priv, "vault-jti-2")
    _, wrong_pub = generate_keypair()
    secret, reason = v.inject("db/password", token, wrong_pub, 1800000100, *_stores())
    assert (secret, reason) == (None, "denied: no valid certificate")
    secret, reason = v.inject(
        "db/password", "garbage.token.here", pub, 1800000100, *_stores()
    )
    assert (secret, reason) == (None, "denied: no valid certificate")
    secret, reason = v.inject("nope", token, pub, 1800000100, *_stores())
    assert (secret, reason) == (None, "missing: no such secret")
    assert [e.event for e in v.audit()] == ["stored", "denied", "denied", "denied"]


def test_expired_cert_denied(keypair, cert_claims):
    priv, pub = keypair
    v = Vault()
    v.store("db/password", b"s3cr3t", 1800000000)
    token = _token(cert_claims, priv, "vault-jti-3")
    secret, reason = v.inject("db/password", token, pub, 1800000301, *_stores())
    assert (secret, reason) == (None, "denied: no valid certificate")


def test_vault_budget():
    v = Vault(max_secrets=2)
    v.store("a", b"1", 1800000000)
    v.store("b", b"2", 1800000000)
    with pytest.raises(ValueError, match="vault full"):
        v.store("c", b"3", 1800000000)


def test_secret_absent_from_transcripts(keypair, cert_claims):
    priv, pub = keypair
    v = Vault()
    v.store("db/password", b"s3cr3t-p4ss", 1800000000)
    token = _token(cert_claims, priv, "vault-jti-4")
    v.inject("db/password", token, pub, 1800000100, *_stores())
    v.inject("db/password", "bad", pub, 1800000100, *_stores())
    transcripts = json.dumps([dataclasses.asdict(e) for e in v.audit()])
    transcripts += repr(v.audit()) + repr(v) + v.live_key_id
    assert "s3cr3t-p4ss" not in transcripts


def test_rotation_invalidates(keypair, cert_claims):
    priv, pub = keypair
    v = Vault()
    v.store("db/password", b"s3cr3t", 1800000000)
    assert v.live_key_id == "k1"
    assert v.rotate(1800000100) == "k2"
    assert v.live_key_id == "k2"
    token = _token(cert_claims, priv, "vault-jti-5")
    secret, reason = v.inject("db/password", token, pub, 1800000100, *_stores())
    assert (secret, reason) == (b"s3cr3t", "ok: injected")
    assert "rotated" in [e.event for e in v.audit()]


def test_audit_bounded():
    v = Vault(max_audit=3)
    for i in range(5):
        v.store(f"s{i}", b"x", 1800000000)
    assert [e.seq for e in v.audit()] == [3, 4, 5]
    assert v.dropped() == 2


def test_erased_unrecoverable(keypair, cert_claims):
    priv, pub = keypair
    v = Vault()
    v.store("db/password", b"s3cr3t", 1800000000)
    v.erase("db/password", 1800000100)
    token = _token(cert_claims, priv, "vault-jti-6")
    secret, reason = v.inject("db/password", token, pub, 1800000100, *_stores())
    assert (secret, reason) == (None, "erased: secret erased")
    assert "erased" in [e.event for e in v.audit()]
    v.store("db/password", b"n3w", 1800000200)
    secret, reason = v.inject("db/password", token, pub, 1800000200, *_stores())
    assert (secret, reason) == (b"n3w", "ok: injected")


def test_erase_unknown_raises():
    v = Vault()
    with pytest.raises(ValueError, match="cannot erase"):
        v.erase("nope", 1800000000)
