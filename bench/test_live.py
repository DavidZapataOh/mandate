import pytest

from bench.live import LiveResult, load_live, save_live, time_live


def test_time_live_reports_wall_times_in_ms_from_its_clock():
    ticks = iter([0.0, 0.010, 0.010, 0.030])
    calls = []
    result = time_live(
        "sandbox.reconcile",
        "increase",
        "one listing",
        lambda: calls.append(1),
        2,
        now=lambda: 1800001000.9,
        timer=lambda: next(ticks),
    )
    assert calls == [1, 1]
    assert result == LiveResult(
        "sandbox.reconcile",
        "increase",
        "2027-01-15T08:16:40Z",
        2,
        15.0,
        19.5,
        20.0,
        "one listing",
    )


def test_live_results_round_trip_and_a_bad_file_is_named(tmp_path):
    a = LiveResult("b.second", "p", "2027-01-15T08:16:40Z", 1, 1.0, 1.0, 1.0, "n")
    z = LiveResult("a.first", "p", "2027-01-15T08:16:40Z", 2, 2.0, 2.0, 2.0, "n")
    assert save_live(a, tmp_path / "live").name == "b.second.json"
    save_live(z, tmp_path / "live")
    assert load_live(tmp_path / "live") == (z, a)
    assert load_live(tmp_path / "absent") == ()
    (tmp_path / "live" / "c.json").write_text('{"name": "c"}')
    with pytest.raises(ValueError, match="^live: c.json unreadable$"):
        load_live(tmp_path / "live")
