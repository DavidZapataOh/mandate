import dataclasses
import json
import time
import tomllib
from pathlib import Path

from bench.job import measure
from bench.jobs import ALL_JOBS
from bench.runner import check_budgets, summarize

BUDGETS = Path(__file__).resolve().parent / "budgets.toml"


def _job(name):
    return next(job for job in ALL_JOBS if job.name == name)


def _slowed(timed, seconds):
    def slow():
        end = time.perf_counter() + seconds
        while time.perf_counter() < end:
            pass
        return timed()

    return slow


def test_every_job_is_within_its_budget(tmp_path):
    results = [measure(job, tmp_path / job.name) for job in ALL_JOBS]
    assert check_budgets(results, BUDGETS) == []


def test_a_path_slowed_by_100_us_breaches_all_three_budgets(tmp_path):
    job = _job("gate.policy.evaluate")
    slowed = dataclasses.replace(
        job, setup=lambda d, c: _slowed(job.setup(d, c), 100e-6), n=200, warmup=20
    )
    breaches = check_budgets([measure(slowed, tmp_path)], BUDGETS)
    assert [b.metric for b in breaches] == [
        "p50_us",
        "p95_us",
        "min_decisions_per_s",
    ]
    assert breaches[0].actual >= 100.0
    assert breaches[0].message.endswith(" exceeds budget 7")


def test_an_attack_that_gets_through_breaches_even_when_fast():
    through = summarize(
        "attacks.templates",
        [1000.0] * 10,
        0.01,
        {"attempts": 70, "unblocked": 1, "moved_cents": 20000},
    )
    assert [b.message for b in check_budgets([through], BUDGETS)] == [
        "attacks.templates.unblocked: actual 1 must be 0",
        "attacks.templates.moved_cents: actual 20000 must be 0",
    ]


def test_a_desk_that_stops_paying_breaches_even_when_fast():
    unpaid = summarize("desk.pay.durable", [5000.0] * 10, 0.05, {"unpaid": 10})
    assert [b.message for b in check_budgets([unpaid], BUDGETS)] == [
        "desk.pay.durable.unpaid: actual 10 must be 0"
    ]


def test_the_published_report_names_every_job_and_size():
    published = json.loads((BUDGETS.parent / "report.json").read_text())
    names = [m["result"]["name"] for m in published["measured"]]
    assert names == [job.name for job in ALL_JOBS]
    with open(BUDGETS, "rb") as f:
        assert list(published["sizes"]) == sorted(tomllib.load(f)["sizes"])
