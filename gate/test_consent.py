import base64
import dataclasses
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gate.cava import CavaAction, Freshness
from gate.certs import generate_keypair, public_key_of
from gate.consent import (
    Consent,
    ConsentLedger,
    HolderApproval,
    certifying_key,
    check_consent,
    consent_bytes,
    key_bytes,
    sign_approval,
    sign_consent,
    verify_signature,
    with_approval,
)
from gate.policy import Intent, Policy, Rule, Verdict
from gate.shim import Mode, RawCall, decide
from gate.state import StateStore

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


HOLDER_SEED = b"\x02" * 32
ONE_TIME_SEED = b"\x81" * 32
CONSENT_KEY = "k9ufLuD3456UL7WUQRkL8gucQ8/MigUaFSSZzzkrejc="
KEY_GOLDEN = (
    b'consent-key/v1:{"consent_key":"k9ufLuD3456UL7WUQRkL8gucQ8/MigUaFSSZzzkrejc=",'
    b'"nonce":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"}'
)
SIGNATURE = (
    "lAOXEpjjaO0B934n4D4TadgDVoQZwKelSPH/gfcBHN6p0pRps6thEVf5Jv6HjqXBL4GWlrbtyG8g"
    "2yaZRHJtBQ=="
)
KEY_SIGNATURE = (
    "+X6h/rc1nPB2yzCHOWZQga63XW1nkEgXyPuJ+sBqm5VRdIT1Ic0gveUeWgXdo7h3Lr2DiGASSkxs"
    "6kctTBbfAA=="
)


def test_key_bytes_golden():
    assert key_bytes(base64.b64decode(CONSENT_KEY), "c0" * 16) == KEY_GOLDEN


@pytest.mark.parametrize(
    ("key", "nonce"),
    [
        (b"\x01" * 31, "c0" * 16),
        (bytearray(32), "c0" * 16),
        ("01" * 16, "c0" * 16),
        (b"\x01" * 32, ""),
        (b"\x01" * 32, "c0 c0"),
    ],
)
def test_key_bytes_rejects_malformed(key, nonce):
    with pytest.raises(ValueError, match="consent: malformed"):
        key_bytes(key, nonce)


def test_an_approval_is_a_one_time_key_the_holder_certifies():
    approval = sign_approval(HOLDER_SEED, UNSIGNED, ONE_TIME_SEED)
    assert approval == HolderApproval(
        signature=base64.b64decode(SIGNATURE),
        consent_key=base64.b64decode(CONSENT_KEY),
        key_signature=base64.b64decode(KEY_SIGNATURE),
    )
    signed = with_approval(UNSIGNED, approval)
    assert (signed.signature, signed.consent_key, signed.key_signature) == (
        approval.signature,
        approval.consent_key,
        approval.key_signature,
    )
    assert consent_bytes(signed) == GOLDEN


def test_each_approval_draws_its_own_consent_key():
    first, second = (sign_approval(HOLDER_SEED, UNSIGNED) for _ in range(2))
    assert first.consent_key != second.consent_key
    assert public_key_of(HOLDER_SEED) not in (first.consent_key, second.consent_key)
    assert first.key_signature != second.key_signature


def test_ledger_bounds_consent_keys():
    ledger = ConsentLedger(max_entries=2)
    for n in (1, 2, 3):
        ledger.consume_key(bytes([n]) * 32)
    assert [ledger.key_used(bytes([n]) * 32) for n in (1, 2, 3)] == [
        False,
        True,
        True,
    ]


def test_the_gate_accepts_a_one_time_key_the_holder_certified():
    signed = sign_consent(HOLDER_SEED, UNSIGNED, ONE_TIME_SEED)
    holder = public_key_of(HOLDER_SEED)
    assert signed.signature == base64.b64decode(SIGNATURE)
    assert check_consent(signed, (holder,), _action(), NOW, ConsentLedger()) == (
        True,
        "ok: consent",
    )


def test_the_holder_key_signing_the_consent_alone_no_longer_approves():
    holder = Ed25519PrivateKey.from_private_bytes(HOLDER_SEED)
    direct = dataclasses.replace(
        UNSIGNED, signature=holder.sign(consent_bytes(UNSIGNED))
    )
    assert check_consent(
        direct, (public_key_of(HOLDER_SEED),), _action(), NOW, ConsentLedger()
    ) == (False, "consent: bad signature")


def test_each_consent_is_signed_by_its_own_key():
    priv, pub = generate_keypair()
    first, second = (sign_consent(priv, UNSIGNED) for _ in range(2))
    assert first.consent_key != second.consent_key
    assert verify_signature(first, (pub,)) and verify_signature(second, (pub,))


def test_a_key_certified_by_another_holder_is_refused():
    _, holder = generate_keypair()
    agent_priv, _ = generate_keypair()
    forged = sign_consent(agent_priv, UNSIGNED)
    assert check_consent(forged, (holder,), _action(), NOW, ConsentLedger()) == (
        False,
        "consent: bad signature",
    )


def test_a_key_certified_for_another_nonce_is_refused():
    other = dataclasses.replace(UNSIGNED, nonce="d0" * 16)
    moved = dataclasses.replace(
        sign_approval(HOLDER_SEED, other, ONE_TIME_SEED),
        signature=base64.b64decode(SIGNATURE),
    )
    holder = public_key_of(HOLDER_SEED)
    assert check_consent(
        with_approval(UNSIGNED, moved), (holder,), _action(), NOW, ConsentLedger()
    ) == (False, "consent: bad signature")


def test_a_consent_signed_by_the_holder_key_itself_is_refused():
    holder = public_key_of(HOLDER_SEED)
    signed = sign_consent(HOLDER_SEED, UNSIGNED, HOLDER_SEED)
    assert signed.consent_key == holder
    assert check_consent(signed, (holder,), _action(), NOW, ConsentLedger()) == (
        False,
        "consent: key reused",
    )


def test_a_consent_key_authorizes_one_payment():
    gate_priv, _ = generate_keypair()
    holder = public_key_of(HOLDER_SEED)
    ledger = ConsentLedger()
    again = dataclasses.replace(UNSIGNED, nonce="d0" * 16)
    first = sign_consent(HOLDER_SEED, UNSIGNED, ONE_TIME_SEED)
    second = sign_consent(HOLDER_SEED, again, ONE_TIME_SEED)
    assert first.consent_key == second.consent_key
    paid = _decide(gate_priv, first, holder, ledger, "a" * 32)
    denied = _decide(gate_priv, second, holder, ledger, "b" * 32)
    assert paid.verdict is Verdict.MET
    assert (denied.verdict, denied.event.reason, denied.certificate) == (
        Verdict.NOT_MET,
        "consent: key reused",
        None,
    )
    assert ledger.key_used(first.consent_key) is True


@pytest.mark.parametrize(
    "change",
    [
        {"consent_key": b""},
        {"consent_key": b"\x01" * 31},
        {"consent_key": CONSENT_KEY},
        {"key_signature": b""},
        {"key_signature": b"\x00" * 64},
        {"signature": b"\x00" * 64},
    ],
)
def test_a_broken_approval_fails_closed(change):
    signed = sign_consent(HOLDER_SEED, UNSIGNED, ONE_TIME_SEED)
    broken = dataclasses.replace(signed, **change)
    holder = public_key_of(HOLDER_SEED)
    assert check_consent(broken, (holder,), _action(), NOW, ConsentLedger()) == (
        False,
        "consent: bad signature",
    )


def test_a_consent_spent_before_a_restart_stays_spent(tmp_path):
    holder_priv, holder_pub = generate_keypair()
    c = sign_consent(holder_priv, UNSIGNED)
    path = tmp_path / "state.db"
    ConsentLedger(state=StateStore(path)).consume(c.nonce, c.expires_at)
    again = ConsentLedger(state=StateStore(path))
    assert check_consent(c, (holder_pub,), _action(), NOW, again) == (
        False,
        "consent: already used",
    )


def test_a_consent_key_spent_before_a_restart_stays_spent(tmp_path):
    c = sign_consent(HOLDER_SEED, UNSIGNED, ONE_TIME_SEED)
    path = tmp_path / "state.db"
    ConsentLedger(state=StateStore(path)).consume_key(c.consent_key, c.expires_at)
    again = ConsentLedger(state=StateStore(path))
    other = dataclasses.replace(UNSIGNED, nonce="d0" * 16)
    reused = sign_consent(HOLDER_SEED, other, ONE_TIME_SEED)
    holder = public_key_of(HOLDER_SEED)
    assert check_consent(reused, (holder,), _action(), NOW, again) == (
        False,
        "consent: key reused",
    )


class _Crash(BaseException):
    pass


def test_a_consent_is_spent_on_disk_before_its_certificate_exists(
    tmp_path, monkeypatch
):
    gate_priv, _ = generate_keypair()
    c = sign_consent(HOLDER_SEED, UNSIGNED, ONE_TIME_SEED)
    path = tmp_path / "state.db"
    ledger = ConsentLedger(state=StateStore(path))

    def crash(*args, **kwargs):
        raise _Crash

    monkeypatch.setattr("gate.shim.issue_certificate", crash)
    with pytest.raises(_Crash):
        _decide(gate_priv, c, public_key_of(HOLDER_SEED), ledger, "a" * 32)
    raw = sqlite3.connect(path)
    query = "SELECT kind, key, expires_at FROM used ORDER BY kind"
    rows = raw.execute(query).fetchall()
    raw.close()
    assert rows == [
        ("consent", c.nonce, c.expires_at),
        ("consent-key", c.consent_key.hex(), c.expires_at),
    ]


def test_a_stored_ledger_is_bounded_by_pruning_not_eviction(tmp_path):
    store = StateStore(tmp_path / "state.db")
    ledger = ConsentLedger(max_entries=1, state=store)
    ledger.consume("n1", NOW)
    ledger.consume("n2", NOW + 10)
    assert ledger.used("n1") and ledger.used("n2")
    store.prune(NOW + 1)
    assert (ledger.used("n1"), ledger.used("n2")) == (False, True)


def test_an_in_memory_ledger_still_evicts_its_oldest():
    ledger = ConsentLedger(max_entries=1)
    ledger.consume("n1")
    ledger.consume_key(b"k1", NOW)
    ledger.consume("n2", NOW)
    ledger.consume_key(b"k2")
    assert (ledger.used("n1"), ledger.used("n2")) == (False, True)
    assert (ledger.key_used(b"k1"), ledger.key_used(b"k2")) == (False, True)


def test_a_crash_between_nonce_and_key_spends_neither(tmp_path, monkeypatch):
    gate_priv, _ = generate_keypair()
    c = sign_consent(HOLDER_SEED, UNSIGNED, ONE_TIME_SEED)
    path = tmp_path / "state.db"
    store = StateStore(path)
    consume = store.consume

    def crash_on_key(kind, key, expires_at):
        if kind == "consent-key":
            raise _Crash
        return consume(kind, key, expires_at)

    monkeypatch.setattr(store, "consume", crash_on_key)
    with pytest.raises(_Crash):
        _decide(
            gate_priv,
            c,
            public_key_of(HOLDER_SEED),
            ConsentLedger(state=store),
            "a" * 32,
        )
    raw = sqlite3.connect(path)
    assert raw.execute("SELECT * FROM used").fetchall() == []
    raw.close()
    again = ConsentLedger(state=StateStore(path))
    assert (again.used(c.nonce), again.key_used(c.consent_key)) == (False, False)


def test_every_paired_key_is_tried_whichever_one_certified(monkeypatch):
    import gate.consent as consent

    signed = sign_consent(HOLDER_SEED, UNSIGNED, ONE_TIME_SEED)
    certifier = public_key_of(HOLDER_SEED)
    others = tuple(generate_keypair()[1] for _ in range(3))
    real = consent._signed
    calls = []

    def counting(key, signature, message):
        calls.append(key)
        return real(key, signature, message)

    monkeypatch.setattr(consent, "_signed", counting)
    for keys in ((certifier, *others), (*others[:2], certifier, others[2])):
        calls.clear()
        assert certifying_key(signed, keys) == certifier
        # One check for the one-time signature, then one per paired key.
        assert len(calls) == 1 + len(keys)


def test_the_first_certifying_key_wins_when_several_verify():
    signed = sign_consent(HOLDER_SEED, UNSIGNED, ONE_TIME_SEED)
    certifier = public_key_of(HOLDER_SEED)
    assert certifying_key(signed, (certifier, certifier)) == certifier


WEAK_ONE_TIME = bytes.fromhex("ee" + "ff" * 30 + "7f")
WEAK_HOLDER = bytes.fromhex("01" + "00" * 31)
# R = the identity point, S = 0: verifies under both keys above for any message.
FORGED = bytes.fromhex("01" + "00" * 63)


def test_a_small_order_one_time_key_certifies_nothing():
    holder = Ed25519PrivateKey.from_private_bytes(HOLDER_SEED)
    certificate = holder.sign(key_bytes(WEAK_ONE_TIME, UNSIGNED.nonce))
    forged = dataclasses.replace(
        UNSIGNED,
        signature=FORGED,
        consent_key=WEAK_ONE_TIME,
        key_signature=certificate,
    )
    assert certifying_key(forged, (public_key_of(HOLDER_SEED),)) is None


def test_a_small_order_holder_key_certifies_nothing():
    forged = dataclasses.replace(
        UNSIGNED, signature=FORGED, consent_key=WEAK_ONE_TIME, key_signature=FORGED
    )
    assert certifying_key(forged, (WEAK_HOLDER,)) is None
