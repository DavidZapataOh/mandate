import json

from bench.job import IN_PROCESS, LOCAL_DISK
from bench.live import LiveResult
from bench.report import Measured, Report, to_json, to_markdown, write_report
from bench.runner import BenchResult, BudgetBreach

HOST = {
    "cpu": "Apple M4",
    "cores": "10",
    "os": "macOS-27.0.1",
    "python": "3.14.3",
    "commit": "f86b5bd",
}
DECIDE = BenchResult("gate.shim.decide", 6000, 10.4, 10.8, 93605.0, {"ops": 6000})
ATTACKS = BenchResult(
    "attacks.templates",
    300,
    990.3,
    1023.4,
    1003.2,
    {"attempts": 2100, "unblocked": 0, "moved_cents": 0},
)
DURABLE = BenchResult("desk.pay.durable", 180, 8002.1, 8319.4, 124.2, {"unpaid": 0})
SANDBOX = LiveResult(
    "sandbox.governed_payment",
    "increase",
    "2027-01-15T08:16:40Z",
    5,
    412.5,
    655.0,
    690.2,
    "gate, certificate, one account transfer and its read",
)
REPORT = Report(
    HOST,
    "2027-01-15T08:16:40Z",
    (Measured(IN_PROCESS, DECIDE), Measured(IN_PROCESS, ATTACKS)),
    {"console.index": 27058},
    (SANDBOX,),
    (),
)
GOLDEN = """# Mandate benchmarks

Measured 2027-01-15T08:16:40Z on Apple M4, 10 cores, macOS-27.0.1, Python 3.14.3, \
commit f86b5bd.
Each path ran three rounds after a warmup; each statistic is the median of its \
round values. Budgets: `bench/budgets.toml`. Reproduce: \
`python -m bench report --dist console/dist`.

## Headline

- Gate decision (`gate.shim.decide`): p50 10.4 µs, p95 10.8 µs, 93,605/s on one \
thread.
- Template attacks that got past their layer: 0 of 2100; cents moved: 0 \
(`attacks.templates`, seven kinds on the simulated bank).

## In process: one thread, fixed inputs

| Path | Samples | p50 µs | p95 µs | per s |
|---|---:|---:|---:|---:|
| gate.shim.decide | 6000 | 10.4 | 10.8 | 93,605 |
| attacks.templates | 300 | 990.3 | 1,023.4 | 1,003 |

## Console build: gzip -9 bytes

| Asset | Bytes |
|---|---:|
| console.index | 27,058 |

## Live: sandbox, network dependent

Owner-run jobs, never part of the gate's numbers above; each row shows when it ran.

| Path | Provider | Measured | Samples | p50 ms | p95 ms | max ms | Includes |
|---|---|---|---:|---:|---:|---:|---|
| sandbox.governed_payment | increase | 2027-01-15T08:16:40Z | 5 | 412.5 | 655.0 \
| 690.2 | gate, certificate, one account transfer and its read |

## Breaches

No breaches.
"""


def test_markdown_keeps_live_numbers_apart_from_the_gate():
    assert to_markdown(REPORT) == GOLDEN


def test_each_label_gets_its_own_table_and_breaches_are_listed():
    breach = BudgetBreach(
        "x", "p50_us", 2.0, 1.0, "x.p50_us: actual 2 exceeds budget 1"
    )
    md = to_markdown(
        Report(HOST, "t", (Measured(LOCAL_DISK, DURABLE),), {}, (), (breach,))
    )
    assert md.split("\n\n")[2:] == [
        "## Headline",
        "- Desk payment, quote to sealed receipt, durable (`desk.pay.durable`): "
        "p50 8,002.1 µs, p95 8,319.4 µs, 124/s on one thread.",
        "## Local disk: in process, SQLite state store, synchronous=FULL",
        "| Path | Samples | p50 µs | p95 µs | per s |\n|---|---:|---:|---:|---:|\n"
        "| desk.pay.durable | 180 | 8,002.1 | 8,319.4 | 124 |",
        "## Live: sandbox, network dependent",
        "Owner-run jobs, never part of the gate's numbers above; each row shows "
        "when it ran.",
        "No live run recorded.",
        "## Breaches",
        "- x.p50_us: actual 2 exceeds budget 1\n",
    ]


def test_json_carries_every_field_and_writes_both_files(tmp_path):
    data = json.loads(to_json(REPORT))
    assert list(data) == [
        "host",
        "measured_at",
        "measured",
        "sizes",
        "live",
        "breaches",
    ]
    assert data["measured"][1] == {
        "label": "in process",
        "result": {
            "name": "attacks.templates",
            "samples": 300,
            "p50_us": 990.3,
            "p95_us": 1023.4,
            "decisions_per_s": 1003.2,
            "counters": {"attempts": 2100, "unblocked": 0, "moved_cents": 0},
        },
    }
    assert data["live"][0]["provider"] == "increase"
    json_path, md_path = write_report(tmp_path / "out", REPORT)
    assert (json_path.name, md_path.name) == ("report.json", "REPORT.md")
    assert md_path.read_text() == GOLDEN
    assert json.loads(json_path.read_text()) == data
