"""Benchmark measurement, statistics, and budget gating."""

import math
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BenchResult:
    """Outcome of measuring one named path."""

    name: str
    samples: int
    p50_us: float
    p95_us: float
    decisions_per_s: float
    counters: dict[str, int]


@dataclass(frozen=True)
class BudgetBreach:
    """One budget violation, or a missing/incomplete budget registration."""

    path: str
    metric: str
    actual: float
    budget: float
    message: str


def percentile(sorted_us: list[float], q: float) -> float:
    """Linear interpolation; rank = q/100 * (n-1).

    Raises ValueError on empty input or q outside [0, 100].
    """
    if not sorted_us:
        raise ValueError("need at least one sample")
    if not 0.0 <= q <= 100.0:
        raise ValueError(f"q must be within [0, 100], got {q}")
    rank = q / 100.0 * (len(sorted_us) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_us[low]
    frac = rank - low
    return sorted_us[low] + (sorted_us[high] - sorted_us[low]) * frac


def summarize(
    name: str, samples_us: list[float], elapsed_s: float, counters: dict[str, int]
) -> BenchResult:
    """Pure stats over measured samples.

    decisions_per_s = len(samples)/elapsed_s, 0.0 when elapsed_s <= 0.
    Empty samples raise ValueError.
    """
    if not samples_us:
        raise ValueError("need at least one sample")
    ordered = sorted(samples_us)
    decisions = len(ordered) / elapsed_s if elapsed_s > 0 else 0.0
    return BenchResult(
        name=name,
        samples=len(ordered),
        p50_us=percentile(ordered, 50),
        p95_us=percentile(ordered, 95),
        decisions_per_s=decisions,
        counters=dict(counters),
    )


def run_bench(
    name: str,
    fn: Callable[[], dict[str, int] | None],
    n: int = 1000,
    warmup: int = 100,
) -> BenchResult:
    """Discard warmup iters; time n iters with perf_counter (us samples).

    Counters sum across measured iters (None -> {}); a non-int counter
    value raises TypeError naming the key.
    """
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    totals: dict[str, int] = {}
    start_all = time.perf_counter()
    for _ in range(n):
        start = time.perf_counter()
        out = fn()
        if out is None:
            out = {}
        samples.append((time.perf_counter() - start) * 1e6)
        for key, value in out.items():
            if not isinstance(value, int):
                raise TypeError(
                    f"counter {key!r} must be int, got {type(value).__name__}"
                )
            totals[key] = totals.get(key, 0) + value
    elapsed = time.perf_counter() - start_all
    return summarize(name, samples, elapsed, totals)


def _missing(name: str) -> BudgetBreach:
    return BudgetBreach(name, "budget", 0.0, 0.0, f"{name}: no budget registered")


def _incomplete(name: str) -> BudgetBreach:
    return BudgetBreach(
        name,
        "budget",
        0.0,
        0.0,
        f"{name}: incomplete budget (need p50_us, p95_us, min_decisions_per_s)",
    )


def _over(name: str, metric: str, actual: float, budget: float) -> BudgetBreach:
    return BudgetBreach(
        name,
        metric,
        actual,
        budget,
        f"{name}.{metric}: actual {actual:g} exceeds budget {budget:g}",
    )


def _gate_result(r: BenchResult, section: dict[str, Any]) -> list[BudgetBreach]:
    if any(k not in section for k in ("p50_us", "p95_us", "min_decisions_per_s")):
        return [_incomplete(r.name)]
    try:
        p50 = section["p50_us"]
        p95 = section["p95_us"]
        min_dps = section["min_decisions_per_s"]
        out: list[BudgetBreach] = []
        if r.p50_us > p50:
            out.append(_over(r.name, "p50_us", r.p50_us, p50))
        if r.p95_us > p95:
            out.append(_over(r.name, "p95_us", r.p95_us, p95))
        if r.decisions_per_s < min_dps:
            out.append(
                BudgetBreach(
                    r.name,
                    "min_decisions_per_s",
                    r.decisions_per_s,
                    min_dps,
                    f"{r.name}.min_decisions_per_s: actual "
                    f"{r.decisions_per_s:g} below budget {min_dps:g}",
                )
            )
        return out
    except TypeError:
        return [_incomplete(r.name)]


def check_budgets(results: list[BenchResult], budgets_path: Path) -> list[BudgetBreach]:
    """Gate p50_us, p95_us (over -> breach) and min_decisions_per_s (under -> breach).

    Missing section -> breach 'no budget registered'. Incomplete section ->
    breach 'incomplete budget'. Never raises on content; an unreadable
    file raises OSError.
    """
    try:
        with open(budgets_path, "rb") as f:
            doc = tomllib.load(f)
    except tomllib.TOMLDecodeError:
        doc = {}
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        paths = {}
    breaches: list[BudgetBreach] = []
    for r in results:
        section = paths.get(r.name)
        if not isinstance(section, dict):
            breaches.append(_missing(r.name))
            continue
        breaches.extend(_gate_result(r, section))
    return breaches
