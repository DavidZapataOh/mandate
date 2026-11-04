from bench.baseline import against, same_host
from bench.runner import BenchResult

M4 = {"cpu": "Apple M4", "cores": "10", "os": "macOS-27.0.1", "python": "3.14.3"}
PUBLISHED = {
    "host": M4,
    "measured": [
        {
            "label": "in process",
            "result": {"name": "registry.append_seal", "p50_us": 2300.0},
        },
        {"label": "in process", "result": {"name": "gate.shim.decide", "p50_us": 10.4}},
    ],
}


def _r(name, p50):
    return BenchResult(name, 180, p50, p50, 1.0, {})


def test_a_p50_over_twice_the_published_one_breaches():
    [b] = against(
        [_r("registry.append_seal", 7068.8), _r("gate.shim.decide", 20.8)], PUBLISHED
    )
    assert (b.path, b.metric, b.actual, b.budget) == (
        "registry.append_seal",
        "p50_us",
        7068.8,
        2300.0,
    )
    assert b.message == (
        "registry.append_seal.p50_us: actual 7068.8 is over 2x the published 2300"
    )


def test_a_new_path_has_no_baseline_and_passes():
    assert against([_r("desk.new", 1e9)], PUBLISHED) == []


def test_only_the_same_cpu_cores_and_python_minor_compare():
    assert same_host(M4, {**M4, "python": "3.14.9", "os": "macOS-27.1"})
    assert not same_host(M4, {**M4, "python": "3.12.13"})
    assert not same_host(M4, {**M4, "cpu": "AMD EPYC 7763 64-Core Processor"})
    assert not same_host(M4, {**M4, "cores": "4"})
