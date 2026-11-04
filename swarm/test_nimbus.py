import pytest

from gate.cava import action_commitment, action_hash
from gate.certs import generate_keypair, read_claims
from gate.shim import canonize
from swarm.nimbus import (
    PINNED,
    NimbusStep,
    ProdTarget,
    certify,
    nimbus_call,
    run_step,
)

NOW = 1800000000
NONCE = "a" * 32
RELEASE_HASH = "afddca8020aa9e06e02c763363165d21dcb9d54fb10572588c3e193805396906"
STALE_HASH = "ec5942f148c56ef5cb07a9f59114e5bf96a95c6313ba3ad41f3769ca37ade512"
EXPORT_HASH = "f4aefe719df7fc5f5b69a2aee1a9872b8768e8f5df2c9c4352d9f725497517ce"
SALT = b"\xa1" * 32
RELEASE_COMMIT = "60ff812621b284b5ae3fdea4c28b73d6532830cc8e80e666a4ffd6f94452c681"
STALE_COMMIT = "767d2eccc1ab9560bc045000e7b2d62488f7893514c801edc9591677749e6acf"


def _run(step):
    priv, pub = generate_keypair()
    target = ProdTarget(pub)
    return run_step(step, priv, target, NOW, NONCE, SALT), target, pub


def test_release_is_certified_then_deployed():
    outcome, target, pub = _run(NimbusStep.RELEASE)
    assert (outcome.layer, outcome.reason, outcome.blocked) == (
        "gate",
        "ok: released",
        False,
    )
    assert (str(outcome.event.verdict), outcome.event.reason) == (
        "MET",
        "rule release-api-v2 satisfied",
    )
    assert action_hash(outcome.action) == RELEASE_HASH
    assert outcome.event.action_hash == RELEASE_COMMIT
    assert action_commitment(outcome.action, SALT) == RELEASE_COMMIT
    assert outcome.salt == SALT
    claims, _ = read_claims(outcome.certificate, pub)
    assert (claims["action_hash"], claims["scope"]) == (
        RELEASE_COMMIT,
        "nimbus:prod-eu",
    )
    assert target.releases == [RELEASE_COMMIT]


def test_poisoned_tool_dies_at_the_mcp_proxy():
    outcome, target, _ = _run(NimbusStep.POISONED_TOOL)
    assert (outcome.layer, outcome.reason, outcome.blocked) == (
        "mcp",
        "denied: tool undeclared",
        True,
    )
    assert (str(outcome.event.verdict), outcome.event.policy_id) == (
        "NOT_MET",
        "manifest:nimbus-mcp",
    )
    assert action_hash(outcome.action) == EXPORT_HASH == outcome.event.action_hash
    assert outcome.salt is None
    assert (outcome.policy.policy_id, outcome.policy.rules) == (
        "manifest:nimbus-mcp",
        (),
    )
    assert (outcome.certificate, target.releases) == (None, [])


def test_stale_migration_matches_no_rule_and_never_reaches_prod():
    outcome, target, _ = _run(NimbusStep.STALE_MIGRATION)
    assert (outcome.layer, outcome.reason, outcome.blocked) == (
        "gate",
        "no rule matches",
        True,
    )
    assert str(outcome.event.verdict) == "NOT_MET"
    assert action_hash(outcome.action) == STALE_HASH
    assert outcome.event.action_hash == STALE_COMMIT
    assert (outcome.certificate, target.releases) == (None, [])


def test_the_current_migration_is_allowed():
    priv, _ = generate_keypair()
    decision = certify(nimbus_call("migrate", "migration-0042"), priv, NOW, NONCE)
    assert decision.event.reason == "rule migrate-0042 satisfied"
    assert decision.certificate is not None


def test_prod_deploys_only_the_certified_action_and_only_once():
    priv, pub = generate_keypair()
    target = ProdTarget(pub)
    decision = certify(nimbus_call("deploy", "api-v2"), priv, NOW, NONCE)
    other = canonize(nimbus_call("deploy", "api-v3"), NONCE, NOW)
    release = canonize(nimbus_call("deploy", "api-v2"), NONCE, NOW)
    assert target.deploy(decision.certificate, other, NOW, decision.salt) == (
        False,
        "mismatch: action hash differs",
    )
    assert target.deploy(decision.certificate, release, NOW, decision.salt) == (
        False,
        "replay: jti consumed",
    )
    assert target.releases == []


def test_prod_refuses_an_expired_certificate():
    priv, pub = generate_keypair()
    decision = certify(nimbus_call("deploy", "api-v2"), priv, NOW, NONCE)
    release = canonize(nimbus_call("deploy", "api-v2"), NONCE, NOW)
    assert ProdTarget(pub).deploy(
        decision.certificate, release, NOW + 301, decision.salt
    ) == (
        False,
        "stale: token expired",
    )


@pytest.mark.parametrize("step", list(NimbusStep))
def test_each_step_ends_as_pinned(step):
    outcome, _, _ = _run(step)
    assert (outcome.layer, outcome.reason) == PINNED[step]
    assert outcome.blocked is (step is not NimbusStep.RELEASE)


def test_prod_refuses_the_release_under_another_salt():
    priv, pub = generate_keypair()
    target = ProdTarget(pub)
    decision = certify(nimbus_call("deploy", "api-v2"), priv, NOW, NONCE, SALT)
    release = canonize(nimbus_call("deploy", "api-v2"), NONCE, NOW)
    assert target.deploy(decision.certificate, release, NOW, b"\xa2" * 32) == (
        False,
        "mismatch: action hash differs",
    )
    assert target.deploy(decision.certificate, release, NOW, SALT) == (
        False,
        "replay: jti consumed",
    )
    assert target.releases == []
