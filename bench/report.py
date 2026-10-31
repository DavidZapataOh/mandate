"""JSON and Markdown rendering for benchmark results."""

import json
from dataclasses import asdict
from pathlib import Path

from bench.runner import BenchResult, BudgetBreach


def to_json(results: list[BenchResult], breaches: list[BudgetBreach]) -> str:
    """indent=2 JSON: {"results": [{name, samples, p50_us, p95_us,
    decisions_per_s, counters}], "breaches": [{path, metric, actual,
    budget, message}]}.
    """
    payload = {
        "results": [asdict(r) for r in results],
        "breaches": [asdict(b) for b in breaches],
    }
    return json.dumps(payload, indent=2)


def to_markdown(results: list[BenchResult], breaches: list[BudgetBreach]) -> str:
    """Starts with '# Benchmark report'; per result '## <name>' +
    'samples: N | p50: X µs | p95: Y µs | N/s: Z'; then '## Breaches'
    with '- <message>' lines, or 'No breaches.'.
    """
    lines = ["# Benchmark report", ""]
    for r in results:
        lines.append(f"## {r.name}")
        lines.append(
            f"samples: {r.samples} | p50: {r.p50_us} µs | "
            f"p95: {r.p95_us} µs | N/s: {r.decisions_per_s}"
        )
        lines.append("")
    lines.append("## Breaches")
    if breaches:
        for b in breaches:
            lines.append(f"- {b.message}")
    else:
        lines.append("No breaches.")
    return "\n".join(lines) + "\n"


def write_report(
    out_dir: Path, results: list[BenchResult], breaches: list[BudgetBreach]
) -> tuple[Path, Path]:
    """mkdir -p out_dir; write bench-report.json + bench-report.md; return
    (json_path, md_path).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "bench-report.json"
    md_path = out_dir / "bench-report.md"
    json_path.write_text(to_json(results, breaches) + "\n")
    md_path.write_text(to_markdown(results, breaches))
    return json_path, md_path
