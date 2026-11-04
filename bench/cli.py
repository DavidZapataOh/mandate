"""``python -m bench gate|report``: measure, gate, and publish the report."""

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

from bench.baseline import FACTOR, against, same_host
from bench.bundle import bundle_sizes
from bench.host import host
from bench.job import measure
from bench.jobs import ALL_JOBS
from bench.live import load_live
from bench.report import Measured, Report, write_report
from bench.runner import BenchResult, BudgetBreach, check_budgets, check_sizes
from gate.state import iso_utc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m bench")
    parser.add_argument("command", choices=("gate", "report"))
    parser.add_argument("--budgets", type=Path, default=Path("bench/budgets.toml"))
    parser.add_argument("--dist", type=Path, metavar="PATH")
    parser.add_argument("--only", action="append", default=[], metavar="NAME")
    parser.add_argument("--jobs", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--out", type=Path, default=Path("bench"))
    parser.add_argument("--live", type=Path, default=Path("bench/live"))
    parser.add_argument("--against", type=Path, metavar="REPORT_JSON")
    parser.add_argument("--factor", type=float, default=FACTOR)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark command line.

    Returns:
        1 on any breach, 2 on an unknown job, else 0.
    """
    args = _parser().parse_args(argv)
    known = {job.name for job in ALL_JOBS}
    for name in args.only:
        if name not in known:
            print(f"bench: unknown job {name}", file=sys.stderr)
            return 2
    jobs = [job for job in ALL_JOBS if not args.only or job.name in args.only]
    if not args.jobs:
        jobs = []
    here = host()
    measured: list[Measured] = []
    with tempfile.TemporaryDirectory() as tmp:
        for job in jobs:
            measured.append(Measured(job.label, measure(job, Path(tmp) / job.name)))
    results: list[BenchResult] = [m.result for m in measured]
    breaches: list[BudgetBreach] = check_budgets(results, args.budgets)
    sizes = {} if args.dist is None else bundle_sizes(args.dist)
    breaches += check_sizes(sizes, args.budgets)
    if args.against is not None:
        published = json.loads(args.against.read_text())
        if same_host(published["host"], here):
            breaches += against(results, published, args.factor)
        else:
            print(f"baseline: published on {published['host'].get('cpu')}, skipped")
    for breach in breaches:
        print(breach.message)
    if args.command == "report":
        report = Report(
            here,
            iso_utc(int(time.time())),
            tuple(measured),
            sizes,
            load_live(args.live),
            tuple(breaches),
        )
        for path in write_report(args.out, report):
            print(f"wrote {path}")
    return 1 if breaches else 0
