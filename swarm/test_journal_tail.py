import json
import os
import time

from swarm.hub import EventHub
from swarm.journal_tail import MAX_PARTIAL, READ_CHUNK, JournalTail
from swarm.test_console_line import EVENT, HOOK_META, LINE_JSON, RECORD


def _record(agent):
    return json.dumps({**RECORD, "agent": agent}) + "\n"


def _agents(hub):
    return [line.subject["agent"] for line in hub.since(0)]


def test_tail_publishes_complete_records(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.write_text(_record("a") + _record("b"))
    hub = EventHub()
    tail = JournalTail(path, hub)
    assert tail.poll() == 2
    assert tail.poll() == 0
    assert _agents(hub) == ["a", "b"]
    assert [line.seq for line in hub.since(0)] == [1, 2]


def test_partial_record_waits_for_its_newline(tmp_path):
    path = tmp_path / "journal.jsonl"
    text = _record("a")
    path.write_text(text[:-10])
    hub = EventHub()
    tail = JournalTail(path, hub)
    assert tail.poll() == 0
    with path.open("a") as handle:
        handle.write(text[-10:])
    assert tail.poll() == 1
    assert _agents(hub) == ["a"]


def test_truncated_journal_is_read_from_its_start(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.write_text(_record("a") + _record("b"))
    hub = EventHub()
    tail = JournalTail(path, hub)
    tail.poll()
    path.write_text(_record("c"))
    assert tail.poll() == 1
    assert _agents(hub) == ["a", "b", "c"]


def test_replaced_journal_is_read_from_its_start(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.write_text(_record("a"))
    hub = EventHub()
    tail = JournalTail(path, hub)
    tail.poll()
    fresh = tmp_path / "fresh.jsonl"
    fresh.write_text(_record("b") + _record("c"))
    os.replace(fresh, path)
    assert tail.poll() == 2
    assert _agents(hub) == ["a", "b", "c"]


def test_malformed_records_are_skipped(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.write_text("not json\n\n" + '{"agent": "x"}\n' + _record("a"))
    hub = EventHub()
    tail = JournalTail(path, hub)
    assert tail.poll() == 1
    assert (tail.skipped, _agents(hub)) == (2, ["a"])


def test_missing_journal_is_waited_for(tmp_path):
    path = tmp_path / "journal.jsonl"
    hub = EventHub()
    tail = JournalTail(path, hub)
    assert tail.poll() == 0
    path.write_text(_record("a"))
    assert tail.poll() == 1


def test_thread_follows_appends(tmp_path):
    path = tmp_path / "journal.jsonl"
    hub = EventHub()
    tail = JournalTail(path, hub, poll_s=0.01)
    tail.start()
    try:
        path.write_text(_record("a"))
        with path.open("a") as handle:
            handle.write(_record("b"))
        deadline = time.monotonic() + 5
        while hub.last_seq < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        tail.stop()
    assert _agents(hub) == ["a", "b"]


def test_thread_survives_a_fault_and_recovers(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.mkdir()
    hub = EventHub()
    tail = JournalTail(path, hub, poll_s=0.01)
    tail.start()
    try:
        deadline = time.monotonic() + 5
        while tail.errors < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert tail.errors >= 2
        path.rmdir()
        path.write_text(_record("a"))
        while hub.last_seq < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        tail.stop()
    assert _agents(hub) == ["a"]


def test_oversized_partial_record_is_dropped(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.write_text("x" * (MAX_PARTIAL + 1))
    hub = EventHub()
    tail = JournalTail(path, hub)
    assert (tail.poll(), tail.poll()) == (0, 0)
    assert tail.skipped == 1
    with path.open("a") as handle:
        handle.write("\n" + _record("a"))
    assert tail.poll() == 1
    assert _agents(hub) == ["a"]


def _with_event(**change):
    return json.dumps({**RECORD, "event": {**EVENT, **change}}) + "\n"


def test_tail_skips_lines_that_are_not_hook_records(tmp_path):
    desk = {
        **json.loads(LINE_JSON),
        "source": "desk",
        "event": None,
        "meta": None,
        "subject": {
            "step": "confirm",
            "quote_id": "q:000001",
            "status": "confirmed",
            "summary": "Pay 1000000.00 USD to evil-666 (ref X) from checking-881",
            "payment_id": "p:000001",
            "reason": None,
        },
    }
    path = tmp_path / "journal.jsonl"
    path.write_text(json.dumps(desk) + "\n" + json.dumps({"v": 1, **RECORD}) + "\n")
    hub = EventHub()
    tail = JournalTail(path, hub)
    assert tail.poll() == 0
    assert (tail.skipped, hub.last_seq) == (2, 0)


def test_tail_skips_records_the_console_cannot_parse(tmp_path):
    bad_meta = {"v": 2, "event": EVENT, "meta": {**HOOK_META, "extra": 1}}
    path = tmp_path / "journal.jsonl"
    path.write_text(
        _record("a").replace('"lat_us": 61.0', '"lat_us": NaN')
        + _record("b").replace('"lat_us": 61.0', '"lat_us": Infinity')
        + _with_event(ts=1800000000.5)
        + _with_event(cert=7)
        + _with_event(lat_us="61")
        + json.dumps({**RECORD, "event": bad_meta})
        + "\n"
        + json.dumps(
            {**RECORD, "event": {**bad_meta, "meta": {**HOOK_META, "model": 1}}}
        )
        + "\n"
        + "[" * 300000
        + "]" * 300000
        + "\n"
        + _record("ok")
    )
    hub = EventHub()
    tail = JournalTail(path, hub)
    assert tail.poll() == 1
    assert (tail.skipped, _agents(hub)) == (8, ["ok"])


def test_large_journal_is_published_over_several_polls(tmp_path):
    record = _record("a")
    count = READ_CHUNK // len(record) + 10
    path = tmp_path / "journal.jsonl"
    path.write_text(record * count)
    hub = EventHub()
    tail = JournalTail(path, hub)
    first = tail.poll()
    assert 0 < first < count
    while tail.poll():
        pass
    assert (hub.last_seq, tail.skipped) == (count, 0)
