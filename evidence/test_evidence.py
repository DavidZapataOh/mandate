import dataclasses
import string

import pytest

from evidence.cooperative import sign_state, verify_state
from evidence.seams import (
    COOPERATIVE_KIND,
    FIXTURE_CONTENT,
    FIXTURE_ENDPOINT,
    ZKTLS_KIND,
    evidence_ref,
    select_best,
    select_cooperative,
    select_zktls,
)
from gate.certs import generate_keypair

TS = 1800000000
NOW = 1800000100
NONCE = "cc11dd22ee33ff440011223344556677"


def _state(private_key):
    return sign_state(
        private_key,
        "checking-881",
        "funds-sufficient",
        50000,
        "USD",
        NONCE,
        TS,
    )


def test_cooperative_verifies(keypair):
    priv, pub = keypair
    state = _state(priv)
    assert state.expires_at == TS + 300
    ok, reason = verify_state(state, pub, NOW)
    assert (ok, reason) == (True, "ok: cooperative")


def test_cooperative_tamper_denied(keypair):
    priv, pub = keypair
    state = _state(priv)
    tampered = dataclasses.replace(state, balance_cents=90000)
    assert verify_state(tampered, pub, NOW) == (
        False,
        "bad-signature: state signature invalid",
    )
    assert verify_state(state, pub, TS + 301) == (False, "stale: state expired")
    _, wrong_pub = generate_keypair()
    assert verify_state(state, wrong_pub, NOW) == (
        False,
        "bad-signature: state signature invalid",
    )


def _is_hex32(text):
    return len(text) == 32 and all(c in string.hexdigits for c in text)


def test_seam_labels(keypair):
    priv, _pub = keypair
    assert (COOPERATIVE_KIND, ZKTLS_KIND) == (
        "cooperative-signed",
        "zktls-attestation",
    )
    assert (FIXTURE_ENDPOINT, FIXTURE_CONTENT) == (
        "tlsn-server-fixture",
        "example-json",
    )
    state = sign_state(
        priv, "checking-881", "funds-sufficient", 50000, "USD", NONCE, TS
    )
    coop = select_cooperative(state)
    zktls = select_zktls(b"presentation-bytes")
    assert coop.startswith("ev:cooperative-signed:") and _is_hex32(
        coop.rsplit(":", 1)[1]
    )
    assert zktls.startswith("ev:zktls-attestation:") and _is_hex32(
        zktls.rsplit(":", 1)[1]
    )
    assert coop != zktls
    with pytest.raises(ValueError, match="unknown evidence kind"):
        evidence_ref("ouija-board", "ab" * 16)


def test_fallback_path(keypair):
    priv, _pub = keypair
    state = sign_state(
        priv, "checking-881", "funds-sufficient", 50000, "USD", NONCE, TS
    )
    assert select_best(state, b"presentation-bytes").startswith("ev:zktls-attestation:")
    assert select_best(state, None).startswith("ev:cooperative-signed:")
    assert select_best(None, b"presentation-bytes").startswith("ev:zktls-attestation:")
    with pytest.raises(ValueError, match="no evidence available"):
        select_best(None, None)
