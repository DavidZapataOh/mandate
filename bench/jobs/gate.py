"""Gate paths on fixed inputs: canonization, policy, certificates, consent."""

import itertools
import os
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bank.api import Bank
from bank.verifier import Verifier
from bench.job import IN_PROCESS, Job, Timed
from gate.approval import freeze_proposal, verify_approval
from gate.cava import CavaAction, Freshness, action_commitment, action_hash
from gate.certs import (
    BitstringRevocation,
    CertClaims,
    SingleUseStore,
    issue_certificate,
    public_key_of,
    verify_certificate,
)
from gate.consent import (
    Consent,
    ConsentLedger,
    certifying_key,
    check_consent,
    sign_consent,
)
from gate.policy import Intent, Policy, Rule, Verdict, evaluate
from gate.shim import Mode, RawCall, decide
from mandate.client import RunRequest, run_governed
from swarm.flow import PAYMENTS_POLICY

KEY = b"\x01" * 32
HOLDER = b"\x02" * 32
NOW = 1800001000

ACTION = CavaAction(
    version="cava/1",
    runtime="mcp",
    executable="bank.pay",
    operation="transfer",
    category="payments",
    targets=(
        "acct:checking-881",
        "merchant:acme-991",
        "amount:USD:20000",
        "to:acme-991",
        "from:checking-881",
        "ref:A-991",
    ),
    reversible=False,
    freshness=Freshness(
        nonce="deadbeef00112233445566778899aabbcc", timestamp=1800000000
    ),
    evidence_refs=("ev:funds-proof-7f3a",),
)
INTENT = Intent(
    amount_cents=20000, currency="USD", recipient="acme-991", reference="A-991"
)
POLICY = Policy(
    policy_id="payments",
    version=1,
    rules=(
        Rule(
            rule_id="pay-exact",
            actor="mcp:bank.pay",
            operation="transfer",
            target="to:acme-991",
            amount_exact=True,
            amount_lte_cents=None,
            approval_required=False,
        ),
    ),
)
CLAIMS = CertClaims(
    action_hash=action_hash(ACTION),
    policy_id="payments",
    policy_version=1,
    verdict=Verdict.MET,
    freshness_nonce="deadbeef00112233445566778899aabbcc",
    issued_at=1800000000,
    expires_at=1800000300,
    scope="mcp:bank.pay:transfer",
    reasoning_commitment="b5" * 32,
    evidence_refs=("ev:funds-proof-7f3a",),
    revocation_index=7,
)
CALL = RawCall(
    runtime="mcp",
    executable="bank.pay",
    operation="transfer",
    args=(("to", "acme-991"), ("amount", "20000"), ("currency", "USD")),
    category="payments",
    evidence_refs=(),
    reversible=False,
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
CONSENTED = CavaAction(
    version="cava/1",
    runtime="mcp",
    executable="bank.pay",
    operation="transfer",
    category="payments",
    targets=("amount:USD:20000", "from:checking-881", "ref:A-991", "to:acme-991"),
    reversible=False,
    freshness=Freshness(nonce="f" * 32, timestamp=NOW),
    evidence_refs=(),
)
GOVERNED = RawCall(
    runtime="muse",
    executable="bank.pay",
    operation="transfer",
    args=(
        ("to", "acme-991"),
        ("amount", "100"),
        ("currency", "USD"),
        ("ref", "A-991"),
        ("from", "checking-881"),
    ),
    category="payments",
    evidence_refs=(),
    reversible=False,
)


def _ops(fn: Callable[[], object]) -> Timed:
    def timed() -> dict[str, int]:
        fn()
        return {"ops": 1}

    return timed


def _hash(_scratch: Path, _stack: ExitStack) -> Timed:
    return _ops(lambda: action_hash(ACTION))


def _commit(_scratch: Path, _stack: ExitStack) -> Timed:
    return _ops(lambda: action_commitment(ACTION, os.urandom(32)))


def _policy(_scratch: Path, _stack: ExitStack) -> Timed:
    return _ops(lambda: evaluate(ACTION, POLICY, INTENT))


def _certs(_scratch: Path, _stack: ExitStack) -> Timed:
    token = issue_certificate(CLAIMS, KEY, "perf-jti")
    public = public_key_of(KEY)

    def timed() -> dict[str, int]:
        verify_certificate(
            token, public, 1800000100, SingleUseStore(), BitstringRevocation()
        )
        return {"ops": 1}

    return timed


def _shim(_scratch: Path, _stack: ExitStack) -> Timed:
    counter = itertools.count()

    def timed() -> dict[str, int]:
        decide(
            CALL,
            POLICY,
            INTENT,
            KEY,
            mode=Mode.ENFORCE,
            now=1800000100,
            nonce=f"perf-{next(counter):06d}",
            timestamp=1800000000,
            scope="perf",
            reasoning_commitment="p" * 64,
            revocation_index=1,
        )
        return {"ops": 1}

    return timed


def _approval(_scratch: Path, _stack: ExitStack) -> Timed:
    payload = freeze_proposal(ACTION, "payments", 1800000000)
    sig = Ed25519PrivateKey.from_private_bytes(KEY).sign(payload.signable_bytes())
    public = public_key_of(KEY)

    def timed() -> dict[str, int]:
        verify_approval(public, payload, sig, ACTION, 1800000100)
        return {"ops": 1}

    return timed


def _consent(_scratch: Path, _stack: ExitStack) -> Timed:
    consent = sign_consent(KEY, UNSIGNED, b"\x80" * 32)
    keys = (public_key_of(KEY),)
    ledger = ConsentLedger()
    if not check_consent(consent, keys, CONSENTED, NOW, ledger)[0]:
        raise ValueError("bench: consent input does not verify")

    def timed() -> dict[str, int]:
        check_consent(consent, keys, CONSENTED, NOW, ledger)
        return {"ops": 1}

    return timed


def _find_holder(_scratch: Path, _stack: ExitStack) -> Timed:
    # Sixteen paired holders, the certifying one last: the most an approval scans.
    paired = tuple(public_key_of(bytes([n]) * 32) for n in range(3, 18))
    paired += (public_key_of(HOLDER),)
    approved = sign_consent(HOLDER, UNSIGNED, b"\x81" * 32)
    if certifying_key(approved, paired) != paired[-1]:
        raise ValueError("bench: holder input does not certify")

    def timed() -> dict[str, int]:
        certifying_key(approved, paired)
        return {"ops": 1}

    return timed


def _governed(_scratch: Path, _stack: ExitStack) -> Timed:
    bank = Bank({"checking-881": 10**15, "acme-991": 0})
    verifier = Verifier(public_key_of(KEY))
    intent = Intent(
        amount_cents=100, currency="USD", recipient="acme-991", reference="A-991"
    )
    counter = itertools.count()

    def timed() -> dict[str, int]:
        n = next(counter)
        result = run_governed(
            RunRequest(
                call=GOVERNED,
                policy=PAYMENTS_POLICY,
                intent=intent,
                private_key=KEY,
                mode=Mode.ENFORCE,
                now=NOW,
                nonce=f"{n:032x}",
                timestamp=NOW,
                scope="muse:bank.pay:transfer",
                reasoning_commitment="b5" * 32,
                revocation_index=n % 1024,
            ),
            bank,
            verifier,
        )
        return {"ops": 1, "unpaid": int(result.payment is None)}

    return timed


GATE_JOBS: tuple[Job, ...] = (
    Job("gate.cava.hash", IN_PROCESS, _hash, 2000, 200),
    Job("gate.cava.commit", IN_PROCESS, _commit, 2000, 200),
    Job("gate.policy.evaluate", IN_PROCESS, _policy, 2000, 200),
    Job("gate.certs.verify", IN_PROCESS, _certs, 2000, 200),
    Job("gate.shim.decide", IN_PROCESS, _shim, 2000, 200),
    Job("gate.approval.verify", IN_PROCESS, _approval, 2000, 200),
    Job("gate.consent.check", IN_PROCESS, _consent, 2000, 200),
    Job("gate.consent.find_holder", IN_PROCESS, _find_holder, 500, 50),
    Job("gate.governed.run", IN_PROCESS, _governed, 1000, 100),
)
