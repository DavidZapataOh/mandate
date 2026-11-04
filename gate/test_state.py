import os
import re
import stat
import threading

import pytest

from gate.registry import LogEntry
from gate.state import NEVER_EXPIRES, StateStore, iso_utc, load_gate_key


def test_the_store_is_private_and_versioned(tmp_path):
    path = tmp_path / "state" / "state.db"
    StateStore(path).close()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    store = StateStore(path)
    store.put("schema", "9")
    store.close()
    with pytest.raises(ValueError, match="^state: schema v9 unsupported$"):
        StateStore(path)


def test_a_key_is_consumed_once_across_reopen(tmp_path):
    path = tmp_path / "state.db"
    first = StateStore(path)
    assert first.consume("jti", "j1", 100) is True
    assert first.consume("jti", "j1", 100) is False
    first.close()
    again = StateStore(path)
    assert (again.used("jti", "j1"), again.consume("jti", "j1", 100)) == (True, False)
    assert again.consume("consent", "j1", 100) is True


def test_prune_drops_only_expired_keys(state_store):
    state_store.consume("jti", "old", 99)
    state_store.consume("jti", "live", 100)
    state_store.consume("idem", "key", NEVER_EXPIRES)
    assert state_store.prune(100) == 1
    assert [state_store.used("jti", k) for k in ("old", "live")] == [False, True]
    assert state_store.used("idem", "key") is True


def test_a_failed_transaction_writes_nothing(state_store):
    with pytest.raises(RuntimeError), state_store.transaction():
        state_store.add_entry(LogEntry(1, "execution", "{}"))
        state_store.put_record("receipt", "pay:000001", "{}")
        raise RuntimeError("crash")
    assert (state_store.entries(), state_store.record("receipt", "pay:000001")) == (
        [],
        None,
    )


def test_one_winner_when_threads_race(state_store):
    wins = []

    def claim():
        wins.append(state_store.consume("jti", "r", 9))

    threads = [threading.Thread(target=claim) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert wins.count(True) == 1


def test_rows_keep_their_order_across_reopen(tmp_path):
    path = tmp_path / "state.db"
    store = StateStore(path)
    for n in (3, 1, 2):
        store.put_record("intent", f"i:00000{n}", str(n))
    store.add_entry(LogEntry(1, "denial", "a"))
    store.add_entry(LogEntry(2, "execution", "b"))
    store.revoke(7)
    store.close()
    again = StateStore(path)
    keys = [k for k, _ in again.records("intent")]
    assert keys == ["i:000003", "i:000001", "i:000002"]
    assert again.entries() == [
        LogEntry(1, "denial", "a"),
        LogEntry(2, "execution", "b"),
    ]
    assert again.revoked() == [7]


def test_genesis_time_is_iso_utc():
    assert iso_utc(1800001000) == "2027-01-15T08:16:40Z"


def test_the_gate_key_is_made_once_and_kept(tmp_path):
    path = tmp_path / "gate.key"
    key = load_gate_key(path)
    assert (len(key), stat.S_IMODE(os.stat(path).st_mode)) == (32, 0o600)
    assert load_gate_key(path) == key


@pytest.mark.parametrize(
    ("mode", "data", "reason"),
    [
        (0o644, b"\x01" * 32, "state: gate key must be private (chmod 600)"),
        (0o600, b"\x01" * 31, "state: gate key must be 32 bytes"),
    ],
)
def test_a_readable_or_short_gate_key_is_refused(tmp_path, mode, data, reason):
    path = tmp_path / "gate.key"
    path.write_bytes(data)
    path.chmod(mode)
    with pytest.raises(ValueError, match=f"^{re.escape(reason)}$"):
        load_gate_key(path)


def test_a_corrupt_store_is_refused_not_reset(tmp_path):
    path = tmp_path / "state.db"
    garbage = b"not a database" * 100
    path.write_bytes(garbage)
    with pytest.raises(ValueError, match="^state: store unreadable$"):
        StateStore(path)
    assert path.read_bytes() == garbage


def test_a_key_write_cut_short_never_becomes_the_key(tmp_path):
    leftover = tmp_path / ".gate.key.crash.tmp"
    leftover.write_bytes(b"\x01" * 5)
    key = load_gate_key(tmp_path / "gate.key")
    assert len(key) == 32
    assert sorted(p.name for p in tmp_path.iterdir()) == ["gate.key"]
