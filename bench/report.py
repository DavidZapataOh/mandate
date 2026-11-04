"""The published benchmark report: JSON and Markdown from one measurement."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from bench.job import LABELS
from bench.live import LiveResult
from bench.runner import BenchResult, BudgetBreach

NETWORK = "sandbox, network dependent"
_HEADLINES = (
    ("gate.shim.decide", "Gate decision"),
    ("gate.governed.run", "Governed payment, gate and bank verifier"),
    ("desk.pay.durable", "Desk payment, quote to sealed receipt, durable"),
)
_ATTACKS = "attacks.templates"


@dataclass(frozen=True)
class Measured:
    """One gated result and the label that says what it includes."""

    label: str
    result: BenchResult


@dataclass(frozen=True)
class Report:
    """Everything one run publishes.

    Args:
        host: Machine, Python and commit the numbers came from.
        measured_at: UTC time of the run.
        measured: Gated results in job order.
        sizes: Console gzip -9 bytes by asset name.
        live: Owner-run live results, never gated.
        breaches: Budget breaches of this run.
    """

    host: dict[str, str]
    measured_at: str
    measured: tuple[Measured, ...]
    sizes: dict[str, int]
    live: tuple[LiveResult, ...]
    breaches: tuple[BudgetBreach, ...]


def to_json(report: Report) -> str:
    """Indented JSON of every field of the report."""
    return json.dumps(asdict(report), indent=2)


def _headline(report: Report) -> list[str]:
    found = {m.result.name: m.result for m in report.measured}
    lines = []
    for name, title in _HEADLINES:
        r = found.get(name)
        if r is not None:
            lines.append(
                f"- {title} (`{name}`): p50 {r.p50_us:,.1f} µs, "
                f"p95 {r.p95_us:,.1f} µs, {r.decisions_per_s:,.0f}/s on one thread."
            )
    attacks = found.get(_ATTACKS)
    if attacks is not None:
        c = attacks.counters
        lines.append(
            "- Template attacks that got past their layer: "
            f"{c.get('unblocked', 0)} of {c.get('attempts', 0)}; "
            f"cents moved: {c.get('moved_cents', 0)} "
            f"(`{_ATTACKS}`, seven kinds on the simulated bank)."
        )
    return lines


def _table(results: list[BenchResult]) -> str:
    rows = [
        "| Path | Samples | p50 µs | p95 µs | per s |",
        "|---|---:|---:|---:|---:|",
    ]
    rows += [
        f"| {r.name} | {r.samples} | {r.p50_us:,.1f} | {r.p95_us:,.1f} "
        f"| {r.decisions_per_s:,.0f} |"
        for r in results
    ]
    return "\n".join(rows)


def _live(live: tuple[LiveResult, ...]) -> str:
    if not live:
        return "No live run recorded."
    rows = [
        "| Path | Provider | Measured | Samples | p50 ms | p95 ms | max ms "
        "| Includes |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    rows += [
        f"| {x.name} | {x.provider} | {x.measured_at} | {x.samples} "
        f"| {x.p50_ms:,.1f} | {x.p95_ms:,.1f} | {x.max_ms:,.1f} | {x.note} |"
        for x in live
    ]
    return "\n".join(rows)


def to_markdown(report: Report) -> str:
    """The report as Markdown: header, headline, a table per label, bytes, live."""
    h = report.host
    blocks = [
        "# Mandate benchmarks",
        f"Measured {report.measured_at} on {h['cpu']}, {h['cores']} cores, "
        f"{h['os']}, Python {h['python']}, commit {h['commit']}.\n"
        "Each path ran three rounds after a warmup; each statistic is the median "
        "of its round values. Budgets: `bench/budgets.toml`. Reproduce: "
        "`python -m bench report --dist console/dist`.",
    ]
    headline = _headline(report)
    if headline:
        blocks += ["## Headline", "\n".join(headline)]
    for label, heading in LABELS.items():
        results = [m.result for m in report.measured if m.label == label]
        if results:
            blocks += [f"## {heading}", _table(results)]
    if report.sizes:
        rows = ["| Asset | Bytes |", "|---|---:|"]
        rows += [f"| {name} | {size:,} |" for name, size in report.sizes.items()]
        blocks += ["## Console build: gzip -9 bytes", "\n".join(rows)]
    blocks += [
        f"## Live: {NETWORK}",
        "Owner-run jobs, never part of the gate's numbers above; each row shows "
        "when it ran.",
        _live(report.live),
        "## Breaches",
    ]
    if report.breaches:
        blocks.append("\n".join(f"- {b.message}" for b in report.breaches))
    else:
        blocks.append("No breaches.")
    return "\n\n".join(blocks) + "\n"


def write_report(out_dir: Path, report: Report) -> tuple[Path, Path]:
    """Write ``report.json`` then ``REPORT.md`` into ``out_dir``.

    Returns:
        ``(json_path, md_path)``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    md_path = out_dir / "REPORT.md"
    json_path.write_text(to_json(report) + "\n")
    md_path.write_text(to_markdown(report))
    return json_path, md_path
