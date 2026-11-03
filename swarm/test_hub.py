import threading

import pytest

from swarm.console_line import ConsoleLine, read_console_line
from swarm.hub import EventHub


def _line(n):
    subject = {
        "agent": f"child-{n}",
        "tool": "edit_file",
        "targets": [],
        "tool_use_id": None,
    }
    return ConsoleLine(0, "hook", None, None, subject, None)


def _seqs(lines):
    return [line.seq for line in lines]


def test_publish_numbers_lines_from_one():
    hub = EventHub()
    stamped = [hub.publish(_line(n)) for n in range(3)]
    assert _seqs(stamped) == [1, 2, 3]
    assert stamped[2].subject["agent"] == "child-2"
    assert hub.last_seq == 3


def test_since_and_get():
    hub = EventHub()
    for n in range(3):
        hub.publish(_line(n))
    assert _seqs(hub.since(0)) == [1, 2, 3]
    assert _seqs(hub.since(1)) == [2, 3]
    assert hub.since(3) == []
    assert hub.get(2).subject["agent"] == "child-1"
    assert (hub.get(0), hub.get(4)) == (None, None)


def test_hub_keeps_only_the_newest():
    hub = EventHub(max_lines=2)
    for n in range(3):
        hub.publish(_line(n))
    assert _seqs(hub.since(0)) == [2, 3]
    assert hub.get(1) is None
    assert hub.get(3).subject["agent"] == "child-2"


def test_concurrent_publishers_get_unique_seqs():
    hub = EventHub(max_lines=4000)

    def burst():
        for n in range(250):
            hub.publish(_line(n))

    threads = [threading.Thread(target=burst) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert _seqs(hub.since(0)) == list(range(1, 2001))


def test_record_appends_lines_published_after_it(tmp_path):
    hub = EventHub()
    hub.publish(_line(0))
    path = tmp_path / "run.jsonl"
    hub.record(path)
    kept = [hub.publish(_line(n)) for n in (1, 2)]
    hub.close()
    hub.publish(_line(3))
    rows = [read_console_line(x) for x in path.read_text().splitlines()]
    assert rows == kept
    assert hub.closed is True


def test_each_hub_has_its_own_epoch():
    a, b = EventHub(), EventHub()
    assert a.epoch != b.epoch
    assert len(a.epoch) == 16 and int(a.epoch, 16) >= 0


class _BrokenFile:
    closed = False

    def write(self, text):
        raise OSError("disk full")

    def flush(self):
        pass

    def close(self):
        self.closed = True


def test_failing_recorder_is_dropped_and_the_line_stays(tmp_path):
    hub = EventHub()
    hub.record(tmp_path / "run.jsonl")
    broken = _BrokenFile()
    hub._record = broken
    stamped = hub.publish(_line(0))
    assert broken.closed is True
    assert hub.recording is False
    assert hub.get(1) == stamped


def test_record_replaces_and_closes_the_old_handle(tmp_path):
    hub = EventHub()
    hub.record(tmp_path / "a.jsonl")
    first = hub._record
    hub.record(tmp_path / "b.jsonl")
    assert first.closed is True
    assert hub.recording is True
    hub.close()
    assert hub.recording is False


def test_record_after_close_is_refused(tmp_path):
    hub = EventHub()
    hub.close()
    with pytest.raises(ValueError, match="hub closed"):
        hub.record(tmp_path / "run.jsonl")
    assert not (tmp_path / "run.jsonl").exists()
