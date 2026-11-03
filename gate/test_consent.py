import dataclasses

import pytest

from gate.cava import CavaAction, Freshness
from gate.certs import generate_keypair
from gate.consent import (
    Consent,
    ConsentLedger,
    check_consent,
    consent_bytes,
    sign_consent,
    verify_signature,
)
from gate.policy import Intent, Policy, Rule, Verdict
from gate.shim import Mode, RawCall, decide

NOW = 1800001000
GOLDEN = (
    b'consent/v1:{"amount_cents":20000,"currency":"USD","expires_at":1800001600,'
    b'"nonce":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0","recipient":"acme-991",'
    b'"reference":"A-991","source":"checking-881"}'
)
UNSIGNED = Consent(
    amount_cents=20000,
    currency="USD",
    recipient="acme-991",
    reference="A-991",
    source="checking-881",
    nonce="c0" * 16,
    expires_at=1800001600,
    signature=b"",
)
TARGETS = ("amount:USD:20000", "from:checking-881", "ref:A-991", "to:acme-991")
POLICY = Policy(
    policy_id="desk",
    version=1,
    rules=(
        Rule(
            rule_id="pay-with-consent",
            actor="mcp:bank.pay",
            operation="transfer",
            target="*",
            amount_exact=True,
            amount_lte_cents=None,
            approval_required=False,
            consent_required=True,
        ),
    ),
)
INTENT = Intent(20000, "USD", "acme-991", "A-991")


def _action(targets=TARGETS):
    return CavaAction(
        version="cava/1",
        runtime="mcp",
        executable="bank.pay",
        operation="transfer",
        category="payments",
        targets=targets,
        reversible=False,
        freshness=Freshness(nonce="f" * 32, timestamp=NOW),
        evidence_refs=(),
    )


def _call():
    return RawCall(
        runtime="mcp",
        executable="bank.pay",
        operation="transfer",
        args=(
            ("amount", "20000"),
            ("currency", "USD"),
            ("from", "checking-881"),
            ("to", "acme-991"),
            ("ref", "A-991"),
        ),
        category="payments",
        evidence_refs=(),
        reversible=False,
    )


def _decide(gate_priv, consent, holder, ledger, nonce, mode=Mode.ENFORCE):
    return decide(
        _call(),
        POLICY,
        INTENT,
        gate_priv,
        mode=mode,
        now=NOW,
        nonce=nonce,
        timestamp=NOW,
        scope="desk",
        reasoning_commitment="00" * 32,
        revocation_index=0,
        consent=consent,
        holder_keys=(holder,),
        consents=ledger,
    )


def test_consent_bytes_golden():
    assert consent_bytes(UNSIGNED) == GOLDEN


@pytest.mark.parametrize(
    "change",
    [
        {"amount_cents": True},
        {"amount_cents": 0},
        {"currency": ""},
        {"recipient": "acmé"},
        {"reference": "A 991"},
        {"expires_at": "1800001600"},
    ],
)
def test_consent_bytes_rejects_malformed(change):
    with pytest.raises(ValueError, match="consent: malformed"):
        consent_bytes(dataclasses.replace(UNSIGNED, **change))


def test_check_consent_ok_and_reasons():
    priv, pub = generate_keypair()
    _, other = generate_keypair()
    signed = sign_consent(priv, UNSIGNED)
    ledger = ConsentLedger()
    assert len(signed.signature) == 64
    assert check_consent(signed, (pub,), _action(), NOW, ledger) == (
        True,
        "ok: consent",
    )
    assert check_consent(None, (pub,), _action(), NOW, ledger) == (
        False,
        "consent: missing",
    )
    assert check_consent(signed, (pub,), _action(), 1800001601, ledger) == (
        False,
        "consent: expired",
    )
    assert check_consent(signed, (other,), _action(), NOW, ledger) == (
        False,
        "consent: bad signature",
    )
    assert ledger.used(signed.nonce) is False


def test_consent_binds_source_and_payee():
    priv, pub = generate_keypair()
    signed = sign_consent(priv, UNSIGNED)
    for wrong in ("from:savings-002", "to:evil-666", "ref:B-1", "amount:USD:20001"):
        prefix = wrong.split(":")[0] + ":"
        targets = tuple(wrong if t.startswith(prefix) else t for t in TARGETS)
        assert check_consent(
            signed, (pub,), _action(targets), NOW, ConsentLedger()
        ) == (False, "consent: action differs")


def test_decide_requires_consent():
    gate_priv, _ = generate_keypair()
    _, holder = generate_keypair()
    d = _decide(gate_priv, None, holder, ConsentLedger(), "a" * 32)
    assert (d.verdict, d.event.reason, d.certificate) == (
        Verdict.NOT_MET,
        "consent: missing",
        None,
    )


def test_consent_replay_denied():
    gate_priv, _ = generate_keypair()
    holder_priv, holder = generate_keypair()
    signed = sign_consent(holder_priv, UNSIGNED)
    ledger = ConsentLedger()
    first = _decide(gate_priv, signed, holder, ledger, "a" * 32)
    assert first.verdict is Verdict.MET and first.certificate is not None
    second = _decide(gate_priv, signed, holder, ledger, "b" * 32)
    assert (second.verdict, second.event.reason, second.certificate) == (
        Verdict.NOT_MET,
        "consent: already used",
        None,
    )


def test_shadow_does_not_consume():
    gate_priv, _ = generate_keypair()
    holder_priv, holder = generate_keypair()
    signed = sign_consent(holder_priv, UNSIGNED)
    ledger = ConsentLedger()
    _decide(gate_priv, signed, holder, ledger, "a" * 32, mode=Mode.SHADOW)
    assert ledger.used(signed.nonce) is False


def test_ledger_is_bounded():
    ledger = ConsentLedger(max_entries=2)
    for nonce in ("n1", "n2", "n3"):
        ledger.consume(nonce)
    assert [ledger.used(n) for n in ("n1", "n2", "n3")] == [False, True, True]


def test_rules_default_to_no_consent(sample_policy):
    assert sample_policy.rules[0].consent_required is False


@pytest.mark.parametrize("bad", ["x" * 64, None, "valid-bytearray"])
def test_mistyped_signature_fails_closed(bad):
    priv, pub = generate_keypair()
    signed = sign_consent(priv, UNSIGNED)
    if bad == "valid-bytearray":
        bad = bytearray(signed.signature)
    forged = dataclasses.replace(signed, signature=bad)
    assert check_consent(forged, (pub,), _action(), NOW, ConsentLedger()) == (
        False,
        "consent: bad signature",
    )


def test_mistyped_holder_keys_are_skipped():
    priv, pub = generate_keypair()
    signed = sign_consent(priv, UNSIGNED)
    keys = ("abc", None, b"short", pub)
    assert check_consent(signed, keys, _action(), NOW, ConsentLedger()) == (
        True,
        "ok: consent",
    )
    assert check_consent(signed, ("abc", None), _action(), NOW, ConsentLedger()) == (
        False,
        "consent: bad signature",
    )


@pytest.mark.parametrize("size", [0, -1])
def test_ledger_rejects_non_positive_bound(size):
    with pytest.raises(ValueError, match="max_entries must be >= 1"):
        ConsentLedger(max_entries=size)


def test_verify_signature_accepts_only_trusted_holder():
    priv, pub = generate_keypair()
    _, other = generate_keypair()
    unsigned = Consent(20000, "USD", "acme-991", "A-991", "checking-881", "n1", 5, b"")
    signed = sign_consent(priv, unsigned)
    assert verify_signature(signed, (pub,)) is True
    assert verify_signature(signed, (other,)) is False
    assert verify_signature(unsigned, (pub,)) is False
