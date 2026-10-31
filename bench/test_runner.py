from pathlib import Path

import pytest

from bench.runner import (
    BenchResult,
    BudgetBreach,
    check_budgets,
    percentile,
    run_bench,
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
