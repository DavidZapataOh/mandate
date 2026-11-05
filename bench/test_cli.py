import json

from bench.cli import main
from bench.host import host

ONE = "gate.policy.evaluate"


def test_report_regenerates_both_files_for_the_chosen_jobs(tmp_path, capsys):
    out = tmp_path / "out"
    assert (
        main(["report", "--only", ONE, "--out", str(out), "--live", str(tmp_path)]) == 0
    )
    data = json.loads((out / "report.json").read_text())
    assert [m["result"]["name"] for m in data["measured"]] == [ONE]
    assert data["measured"][0]["result"]["samples"] == 6000
    assert set(data["host"]) == {"cpu", "cores", "os", "python", "commit"}
    assert f"| {ONE} | 6000 |" in (out / "REPORT.md").read_text()
    assert capsys.readouterr().out.splitlines() == [
        f"wrote {out / 'report.json'}",
        f"wrote {out / 'REPORT.md'}",
    ]


def test_gate_fails_on_a_breach_and_writes_nothing(tmp_path, capsys):
    tight = tmp_path / "budgets.toml"
    tight.write_text(
        f'[paths."{ONE}"]\np50_us = 0.001\np95_us = 1e9\nmin_decisions_per_s = 0.0\n'
    )
    assert main(["gate", "--only", ONE, "--budgets", str(tight)]) == 1
    [line] = capsys.readouterr().out.splitlines()
    assert line.startswith(f"{ONE}.p50_us: actual ")
    assert line.endswith(" exceeds budget 0.001")
    assert list(tmp_path.iterdir()) == [tight]


def test_an_unknown_job_is_refused(capsys):
    assert main(["gate", "--only", "gate.typo"]) == 2
    assert capsys.readouterr().err == "bench: unknown job gate.typo\n"


def _published(path, cpu_host):
    path.write_text(
        json.dumps(
            {
                "host": cpu_host,
                "measured": [
                    {"label": "in process", "result": {"name": ONE, "p50_us": 0.001}}
                ],
            }
        )
    )
    return str(path)


def test_a_report_from_this_host_is_compared(tmp_path, capsys):
    mine = _published(tmp_path / "report.json", host())
    assert main(["gate", "--only", ONE, "--against", mine]) == 1
    [line] = capsys.readouterr().out.splitlines()
    assert line.startswith(f"{ONE}.p50_us: actual ")
    assert line.endswith(" is over 2x the published 0.001")


def test_a_report_from_another_host_is_not_compared(tmp_path, capsys):
    # This host in every field but the CPU, so no runner can match it.
    elsewhere = {**host(), "cpu": "Elsewhere CPU 9000"}
    other = _published(tmp_path / "report.json", elsewhere)
    assert main(["gate", "--only", ONE, "--against", other]) == 0
    assert capsys.readouterr().out == (
        "baseline: published on Elsewhere CPU 9000, skipped\n"
    )


def test_gate_sizes_a_build_without_running_jobs(tmp_path, capsys):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "a.js").write_bytes(b"a" * 1000)
    (tmp_path / "index.html").write_text('<script src="/console/assets/a.js">')
    budgets = tmp_path / "budgets.toml"
    budgets.write_text(
        '[sizes."console.index"]\nmax_gzip_bytes = 28\n'
        '[sizes."console.lazy"]\nmax_gzip_bytes = 0\n'
    )
    args = ["gate", "--no-jobs", "--dist", str(tmp_path), "--budgets", str(budgets)]
    assert main(args) == 1
    assert capsys.readouterr().out == (
        "console.index.max_gzip_bytes: actual 29 exceeds budget 28\n"
    )
