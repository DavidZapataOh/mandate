from pathlib import Path

import pytest

from bench.runner import (
    BenchResult,
    BudgetBreach,
    check_budgets,
    check_sizes,
    combine,
    percentile,
    run_bench,
    run_rounds,
    summarize,
)


def test_percentile_linear_interpolation():
    assert percentile([0.0, 100.0, 200.0, 300.0], 25) == 75.0
    assert percentile([0.0, 100.0, 200.0, 300.0], 50) == 150.0
    assert percentile([0.0, 100.0, 200.0, 300.0], 75) == 225.0


def test_percentile_rejects_empty_and_bad_q():
    with pytest.raises(ValueError):
        percentile([], 50)
    with pytest.raises(ValueError):
        percentile([1.0], 101)


def test_summarize_computes_stats():
    r = summarize("x", [10.0] * 100, 0.05, {})
    assert isinstance(r, BenchResult)
    assert (r.name, r.samples) == ("x", 100)
    assert (r.p50_us, r.p95_us) == (10.0, 10.0)
    assert r.decisions_per_s == 2000.0


def test_summarize_guards_empty_and_zero_elapsed():
    with pytest.raises(ValueError):
        summarize("x", [], 1.0, {})
    assert summarize("x", [5.0], 0.0, {}).decisions_per_s == 0.0


def test_run_bench_sums_counters_and_reports_schema():
    r = run_bench("dummy", lambda: {"ok": 1}, n=50, warmup=5)
    assert (r.name, r.samples) == ("dummy", 50)
    assert r.counters == {"ok": 50}
    assert r.p50_us >= 0.0


def test_run_bench_rejects_non_int_counter():
    with pytest.raises(TypeError):
        run_bench("bad", lambda: {"x": 1.5}, n=2, warmup=0)


TOML = """[paths.demo]
p50_us = 100.0
p95_us = 200.0
min_decisions_per_s = 10.0
"""


def _write(tmp_path: Path, text: str = TOML) -> Path:
    p = tmp_path / "budgets.toml"
    p.write_text(text)
    return p


def _result(**kw):
    base = {
        "name": "demo",
        "samples_us": [10.0] * 10,
        "elapsed_s": 0.001,
        "counters": {},
    }
    base.update(kw)
    return summarize(
        base.pop("name"), base["samples_us"], base["elapsed_s"], base["counters"]
    )


def test_gate_passes_within_budget(tmp_path):
    assert check_budgets([_result()], _write(tmp_path)) == []


def test_gate_breaches_over_p95(tmp_path):
    [b] = check_budgets([_result(samples_us=[10.0] * 9 + [500.0])], _write(tmp_path))
    assert isinstance(b, BudgetBreach)
    assert (b.path, b.metric, b.budget) == ("demo", "p95_us", 200.0)
    assert b.actual == pytest.approx(279.5)
    assert b.message == "demo.p95_us: actual 279.5 exceeds budget 200"


def test_gate_fails_closed_on_missing_or_incomplete_budget(tmp_path):
    [missing] = check_budgets([_result(name="ghost")], _write(tmp_path))
    assert missing.message == "ghost: no budget registered"
    [partial] = check_budgets(
        [_result()], _write(tmp_path, "[paths.demo]\np50_us = 100.0\n")
    )
    assert partial.message == (
        "demo: incomplete budget (need p50_us, p95_us, min_decisions_per_s)"
    )


def test_combine_takes_the_median_of_each_round_statistic():
    rounds = [
        BenchResult("x", 100, 10.0, 12.0, 100.0, {"ops": 100}),
        BenchResult("x", 100, 30.0, 50.0, 300.0, {"ops": 100}),
        BenchResult("x", 100, 20.0, 25.0, 200.0, {"ops": 100, "bad": 1}),
    ]
    assert combine("x", rounds) == BenchResult(
        "x", 300, 20.0, 25.0, 200.0, {"ops": 300, "bad": 1}
    )


def test_combine_needs_a_round():
    with pytest.raises(ValueError, match="^need at least one round$"):
        combine("x", [])


def test_run_rounds_times_every_round_after_one_warmup():
    calls = []
    result = run_rounds("x", lambda: calls.append(1) or {"ops": 1}, 5, 2, rounds=3)
    assert (len(calls), result.samples, result.counters) == (17, 15, {"ops": 15})


ZERO = TOML + 'zero_counters = ["moved_cents"]\n'


def test_a_zero_counter_must_be_counted_and_zero(tmp_path):
    budgets = _write(tmp_path, ZERO)
    assert check_budgets([_result(counters={"moved_cents": 0})], budgets) == []
    [moved] = check_budgets([_result(counters={"moved_cents": 3})], budgets)
    assert (moved.metric, moved.actual) == ("moved_cents", 3.0)
    assert moved.message == "demo.moved_cents: actual 3 must be 0"
    [absent] = check_budgets([_result()], budgets)
    assert absent.message == "demo.moved_cents: not counted"


SIZES = '[sizes."console.index"]\nmax_gzip_bytes = 100\n'


def test_sizes_breach_over_budget_and_fail_closed_without_one(tmp_path):
    budgets = _write(tmp_path, SIZES)
    assert check_sizes({"console.index": 100}, budgets) == []
    [over] = check_sizes({"console.index": 101}, budgets)
    assert (over.path, over.metric, over.actual, over.budget) == (
        "console.index",
        "max_gzip_bytes",
        101.0,
        100.0,
    )
    assert over.message == (
        "console.index.max_gzip_bytes: actual 101 exceeds budget 100"
    )
    [ghost] = check_sizes({"console.ghost": 1}, budgets)
    assert ghost.message == "console.ghost: no budget registered"
