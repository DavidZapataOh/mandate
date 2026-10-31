import dataclasses

import pytest

from bench.runner import run_bench
from gate.policy import Policy, Rule, Verdict, evaluate, matched_rule


def _rule(**kw):
    base = {
        "rule_id": "r",
        "actor": "mcp:bank.pay",
        "operation": "transfer",
        "target": "to:acme-991",
        "amount_exact": True,
        "amount_lte_cents": None,
        "approval_required": False,
    }
    base.update(kw)
    return Rule(**base)


def _policy(*rules):
    return Policy(policy_id="p", version=1, rules=rules)


@pytest.mark.parametrize(
    ("rule_kw", "verdict", "reason"),
    [
        ({}, Verdict.MET, "rule r satisfied"),
        ({"actor": "mcp:other"}, Verdict.NOT_MET, "no rule matches"),
        ({"operation": "refund"}, Verdict.NOT_MET, "no rule matches"),
        ({"target": "to:evil"}, Verdict.NOT_MET, "no rule matches"),
        (
            {"amount_lte_cents": 100},
            Verdict.NOT_MET,
            "amount exceeds ceiling",
        ),
    ],
)
def test_verdict_matrix(sample_action, sample_intent, rule_kw, verdict, reason):
    v, reasons = evaluate(sample_action, _policy(_rule(**rule_kw)), sample_intent)
    assert v is verdict
    assert reasons == (reason,)


def test_amount_and_currency_checks(sample_action, sample_intent):
    rich = dataclasses.replace(sample_intent, amount_cents=20001)
    v, reasons = evaluate(sample_action, _policy(_rule()), rich)
    assert (v, reasons) == (Verdict.NOT_MET, ("amount differs from intent",))
    eur = dataclasses.replace(sample_action, targets=("amount:EUR:20000",))
    v, reasons = evaluate(eur, _policy(_rule(target="*")), sample_intent)
    assert (v, reasons) == (Verdict.NOT_MET, ("currency mismatch",))
    wild = _rule(actor="*", operation="*", target="*")
    v, reasons = evaluate(sample_action, _policy(wild), sample_intent)
    assert (v, reasons) == (Verdict.MET, ("rule r satisfied",))


def test_first_match_wins(sample_action, sample_intent):
    first = _rule(rule_id="first")
    second = _rule(rule_id="second")
    v, reasons = evaluate(sample_action, _policy(first, second), sample_intent)
    assert reasons == ("rule first satisfied",)
    assert matched_rule(sample_action, _policy(second, first)) is second
    assert matched_rule(sample_action, _policy()) is None


def test_no_ai_claim(sample_action, sample_intent):
    no_amount = dataclasses.replace(sample_action, targets=("to:acme-991",))
    v, reasons = evaluate(no_amount, _policy(_rule()), sample_intent)
    assert v is Verdict.NOT_CHECKABLE
    assert reasons == ("amount not stated",)
    malformed = dataclasses.replace(
        sample_action, targets=("amount:USD:twenty", "to:acme-991")
    )
    v, reasons = evaluate(malformed, _policy(_rule()), sample_intent)
    assert v is Verdict.NOT_CHECKABLE
    assert reasons == ("amount target malformed",)


def test_evaluate_bench_measures_real_path(sample_action, sample_policy, sample_intent):
    action = sample_action
    policy = sample_policy
    intent = sample_intent

    def _once():
        evaluate(action, policy, intent)
        return {"evals": 1}

    r = run_bench("gate.policy.evaluate", _once, n=50, warmup=5)
    assert (r.name, r.samples) == ("gate.policy.evaluate", 50)
    assert r.counters == {"evals": 50}
    assert r.p50_us >= 0.0
