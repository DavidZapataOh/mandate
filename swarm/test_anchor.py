import dataclasses

import pytest

from gate.certs import (
    BitstringRevocation,
    CertClaims,
    SingleUseStore,
    generate_keypair,
    issue_certificate,
    issue_sd_jwt,
    verify_certificate,
)
from gate.policy import Verdict
from swarm.anchor import ReasoningAnchor, anchor_from, verify_anchor
from swarm.conftest import REASONING, TRACE, message, tool_call

ANCHOR_1 = "ecdf64cc119eedfb70667704cdb4f24c8c26cdfee47d2f628fd095dc2ab139f6"


def _anchor():
    return ReasoningAnchor(
        v=1, model="muse-spark-1.3", response_id="resp_1", blobs=("E1",)
    )


def test_anchor_digest_golden():
    assert _anchor().digest() == ANCHOR_1


@pytest.mark.parametrize(
    "change",
    [
        {"model": "muse-wonder-1.0"},
        {"response_id": "resp_2"},
        {"blobs": ("E2",)},
        {"blobs": ("E1", "E1")},
    ],
)
def test_anchor_detects_substitution(change):
    assert dataclasses.replace(_anchor(), **change).digest() != ANCHOR_1


def test_anchor_order_matters():
    a = dataclasses.replace(_anchor(), blobs=("E1", "E2"))
    b = dataclasses.replace(_anchor(), blobs=("E2", "E1"))
    assert a.digest() != b.digest()


def test_anchor_from_response():
    second = dict(REASONING, id="rs_2", encrypted_content="E2")
    output = (REASONING, tool_call(), second)
    assert anchor_from(TRACE, output) == ReasoningAnchor(
        v=1, model="muse-spark-1.3", response_id="resp_1", blobs=("E1", "E2")
    )


def test_anchor_without_reasoning_items():
    anchor = anchor_from(TRACE, (message("hi"),))
    assert anchor.blobs == ()
    assert anchor.digest() != ANCHOR_1


def test_anchor_rejects_redacted_reasoning():
    bare = {k: v for k, v in REASONING.items() if k != "encrypted_content"}
    with pytest.raises(ValueError, match="encrypted_content"):
        anchor_from(TRACE, (bare,))


def test_anchor_json_roundtrip():
    text = _anchor().to_json()
    assert text == (
        '{"blobs":["E1"],"model":"muse-spark-1.3","response_id":"resp_1","v":1}'
    )
    assert ReasoningAnchor.from_json(text) == _anchor()


def test_anchor_json_rejects_unknown_version():
    text = '{"blobs":[],"model":"m","response_id":"r","v":2}'
    with pytest.raises(ValueError, match="unsupported anchor version"):
        ReasoningAnchor.from_json(text)
    with pytest.raises(ValueError, match="malformed anchor"):
        ReasoningAnchor.from_json("{}")


ISSUED = 1800000000


def _cert(private_key, commitment):
    claims = CertClaims(
        action_hash="aa" * 32,
        policy_id="payments",
        policy_version=1,
        verdict=Verdict.MET,
        freshness_nonce="n" * 32,
        issued_at=ISSUED,
        expires_at=ISSUED + 300,
        scope="muse-bill-payer",
        reasoning_commitment=commitment,
        evidence_refs=(),
        revocation_index=0,
    )
    return issue_certificate(claims, private_key, "jti-anchor-1")


def test_verify_anchor_bound():
    priv, pub = generate_keypair()
    token = _cert(priv, ANCHOR_1)
    assert verify_anchor(_anchor(), token, pub) == (True, "ok: anchor bound")


def test_verify_anchor_tampered():
    priv, pub = generate_keypair()
    token = _cert(priv, ANCHOR_1)
    forged = dataclasses.replace(_anchor(), blobs=("E9",))
    assert verify_anchor(forged, token, pub) == (False, "mismatch: reasoning differs")


def test_verify_anchor_wrong_key():
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    token = _cert(priv, ANCHOR_1)
    assert verify_anchor(_anchor(), token, other_pub) == (
        False,
        "bad-signature: eddsa mismatch",
    )


def test_verify_anchor_does_not_consume():
    priv, pub = generate_keypair()
    token = _cert(priv, ANCHOR_1)
    assert verify_anchor(_anchor(), token, pub)[0] is True
    assert verify_anchor(_anchor(), token, pub)[0] is True
    assert verify_certificate(
        token, pub, ISSUED + 10, SingleUseStore(), BitstringRevocation()
    ) == (True, "ok: verified")


def test_anchor_rejects_newline_blobs():
    with pytest.raises(ValueError, match="without newlines"):
        ReasoningAnchor(1, "m", "r", ("a\nb", "c"))
    with pytest.raises(ValueError, match="malformed anchor"):
        ReasoningAnchor.from_json(
            '{"blobs":["a\\nb","c"],"model":"m","response_id":"r","v":1}'
        )
    with pytest.raises(ValueError, match="malformed anchor"):
        ReasoningAnchor.from_json('{"blobs":[""],"model":"m","response_id":"r","v":1}')


def test_anchor_rejects_unsupported_version():
    with pytest.raises(ValueError, match="unsupported anchor version"):
        ReasoningAnchor(2, "m", "r", ())
    with pytest.raises(ValueError, match="unsupported anchor version"):
        ReasoningAnchor(True, "m", "r", ())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unsupported anchor version"):
        ReasoningAnchor.from_json('{"v":2,"extra":1}')


def test_verify_anchor_without_commitment():
    priv, pub = generate_keypair()
    claims = CertClaims(
        action_hash="aa" * 32,
        policy_id="payments",
        policy_version=1,
        verdict=Verdict.MET,
        freshness_nonce="n" * 32,
        issued_at=ISSUED,
        expires_at=ISSUED + 300,
        scope="muse-bill-payer",
        reasoning_commitment=ANCHOR_1,
        evidence_refs=(),
        revocation_index=0,
    )
    token, _ = issue_sd_jwt(claims, priv, "jti-sd", ("reasoning_commitment",))
    assert verify_anchor(_anchor(), token, pub) == (
        False,
        "malformed: no reasoning commitment",
    )
