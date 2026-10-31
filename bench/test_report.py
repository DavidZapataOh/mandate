import json

from bench.report import to_json, to_markdown, write_report
from bench.runner import summarize


def _result():
    return summarize("demo", [10.0] * 10, 0.001, {"ok": 10})


def test_json_schema():
    d = json.loads(to_json([_result()], []))
    assert list(d) == ["results", "breaches"]
    assert d["results"][0]["name"] == "demo"
    assert d["results"][0]["counters"] == {"ok": 10}
    assert d["breaches"] == []


def test_markdown_markers():
    md = to_markdown([_result()], [])
    assert md.startswith("# Benchmark report\n")
    assert "## demo" in md and "No breaches." in md


def test_write_report_writes_both_files(tmp_path):
    jp, mp = write_report(tmp_path / "out", [_result()], [])
    assert (jp.name, mp.name) == ("bench-report.json", "bench-report.md")
    assert jp.exists() and mp.exists()
