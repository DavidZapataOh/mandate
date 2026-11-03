import jwt

from gate.certs import (
    EVENT_TYPE,
    BitstringRevocation,
    SingleUseStore,
    disclose,
    issue_certificate,
    issue_sd_jwt,
    read_claims,
    verify_certificate,
    verify_sd_jwt,
)


def test_offline_verify_pubkey_only(keypair, cert_claims):
    private_key, public_key = keypair
    token = issue_certificate(cert_claims, private_key, "jti-1")
    ok, reason = verify_certificate(
        token,
        public_key,
        1800000100,
        SingleUseStore(),
        BitstringRevocation(),
        consume=False,
    )
    assert (ok, reason) == (True, "ok: verified")
    head, sig = token.rsplit(".", 1)
    flip = "A" if sig[10] != "A" else "B"
    bad = f"{head}.{sig[:10]}{flip}{sig[11:]}"
    ok, reason = verify_certificate(
        bad,
        public_key,
        1800000100,
        SingleUseStore(),
        BitstringRevocation(),
        consume=False,
    )
    assert (ok, reason) == (False, "bad-signature: eddsa mismatch")


def test_secevent_shape(keypair, cert_claims):
    private_key, _ = keypair
    token = issue_certificate(cert_claims, private_key, "jti-shape")
    header = jwt.get_unverified_header(token)
    assert (header["alg"], header["typ"]) == ("EdDSA", "secevent+jwt")
    payload = jwt.decode(token, options={"verify_signature": False})
    assert (payload["iss"], payload["aud"]) == ("mandate", "mandate-verifiers")
    assert payload["jti"] == "jti-shape"
    event = payload["events"][EVENT_TYPE]
    assert event["action_hash"] == cert_claims.action_hash
    assert event["verdict"] == "MET"


def test_replay_rejected(keypair, cert_claims):
    private_key, public_key = keypair
    token = issue_certificate(cert_claims, private_key, "jti-once")
    store = SingleUseStore()
    revoked = BitstringRevocation()
    ok, _ = verify_certificate(token, public_key, 1800000100, store, revoked)
    assert ok is True
    ok, reason = verify_certificate(token, public_key, 1800000100, store, revoked)
    assert (ok, reason) == (False, "replay: jti consumed")


def test_store_evicts_oldest_first():
    store = SingleUseStore(max_entries=2)
    assert store.consume("a") is True
    assert store.consume("b") is True
    assert store.consume("c") is True
    assert len(store) == 2
    assert store.consume("a") is True


def test_revoked_and_stale_reject(keypair, cert_claims):
    private_key, public_key = keypair
    token = issue_certificate(cert_claims, private_key, "jti-r")
    store = SingleUseStore()
    revoked = BitstringRevocation()
    revoked.revoke(7)
    ok, reason = verify_certificate(
        token, public_key, 1800000100, store, revoked, consume=False
    )
    assert (ok, reason) == (False, "revoked: bit set")
    clean = BitstringRevocation()
    ok, reason = verify_certificate(
        token, public_key, 1800000400, store, clean, consume=False
    )
    assert (ok, reason) == (False, "stale: token expired")
    ok, reason = verify_certificate(
        token, public_key, 1799999999, store, clean, consume=False
    )
    assert (ok, reason) == (False, "premature: issued in future")


def test_discloses_subset_only(keypair, cert_claims):
    private_key, public_key = keypair
    token, disclosures = issue_sd_jwt(
        cert_claims, private_key, "jti-sd", ("scope", "reasoning_commitment")
    )
    sandwich = disclose(token, disclosures, ("scope",))
    visible, ok, reason = verify_sd_jwt(sandwich, public_key, 1800000100)
    assert (ok, reason) == (True, "ok: verified")
    assert visible["scope"] == cert_claims.scope
    assert "reasoning_commitment" not in visible
    assert visible["action_hash"] == cert_claims.action_hash
    tampered = sandwich[:-4] + "AAAA"
    _, ok, reason = verify_sd_jwt(tampered, public_key, 1800000100)
    assert (ok, reason) == (False, "tampered: disclosure digest unknown")


def test_bad_public_key_is_a_reason(keypair, cert_claims):
    private_key, _ = keypair
    token = issue_certificate(cert_claims, private_key, "jti-k")
    bad = (None, "malformed: bad public key")
    assert read_claims("x.y.z", b"short") == bad
    store, clean = SingleUseStore(), BitstringRevocation()
    assert verify_certificate(token, b"short", 1800000100, store, clean) == (
        False,
        "malformed: bad public key",
    )
