"""Durable desk state: one SQLite file shared by the gate, the desk and the ledger."""

import json
import os
import sqlite3
import stat
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from gate.registry import LogEntry

SCHEMA_VERSION = 1
NEVER_EXPIRES = 2**62

_KEY_LEN = 32
_PRIVATE_FILE = 0o600
_PRIVATE_DIR = 0o700
_GROUP_OTHER_BITS = 0o077

_TABLES = (
    "CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS entries"
    " (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, body TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS seals (seq_to INTEGER PRIMARY KEY, seal TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS used (kind TEXT NOT NULL, key TEXT NOT NULL,"
    " expires_at INTEGER NOT NULL, PRIMARY KEY (kind, key))",
    "CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, key TEXT NOT NULL,"
    " value TEXT NOT NULL, PRIMARY KEY (kind, key))",
    "CREATE TABLE IF NOT EXISTS revoked (idx INTEGER PRIMARY KEY)",
)


def iso_utc(ts: int) -> str:
    """Format a Unix timestamp as ISO 8601 UTC (`%Y-%m-%dT%H:%M:%SZ`)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_empty(path: Path) -> None:
    """Create `path` empty with mode 0600 unless it already exists."""
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, _PRIVATE_FILE)
    except FileExistsError:
        return
    os.close(fd)
    _fsync_dir(path.parent)


def _check_private(st: os.stat_result, what: str, mode: str) -> None:
    """Refuse a state file that is not this user's own private regular file."""
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"state: {what} must be a regular file")
    if st.st_uid != os.geteuid():
        raise ValueError(f"state: {what} must be owned by this user")
    if st.st_mode & _GROUP_OTHER_BITS:
        raise ValueError(f"state: {what} must be private (chmod {mode})")


def _publish_key(path: Path) -> None:
    """Write a fresh key beside `path`, then link it into place in one step.

    A crash before the link leaves only a temporary file, never a short key;
    a key someone else already published wins.
    """
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        try:
            os.write(fd, os.urandom(_KEY_LEN))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temp, path)
        except FileExistsError:
            pass
    finally:
        os.unlink(temp)
    _fsync_dir(path.parent)


class StateStore:
    """One private SQLite file holding the desk's durable state.

    Every method is safe to call from any thread; `transaction()` groups
    several writes into one atomic commit.
    """

    def __init__(self, path: Path) -> None:
        """Open (or create) the store at `path`.

        Args:
            path: The database file; its directory is created 0700 and the
                file 0600 when missing.

        Raises:
            ValueError: The file is a link, not this user's, readable by group
                or others, not a readable SQLite database, or written by an
                unsupported schema version.
        """
        self._path = path
        if not path.parent.exists():
            path.parent.mkdir(mode=_PRIVATE_DIR, parents=True)
            path.parent.chmod(_PRIVATE_DIR)
        _create_empty(path)
        # It holds every holder copy and every journaled certificate.
        _check_private(os.lstat(path), "store", "600")
        self._lock = threading.RLock()
        self._depth = 0
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        try:
            self._open()
        except sqlite3.OperationalError:
            self._db.close()
            raise
        except sqlite3.DatabaseError as exc:
            self._db.close()
            raise ValueError("state: store unreadable") from exc
        except BaseException:
            self._db.close()
            raise

    def _open(self) -> None:
        self._db.execute("PRAGMA journal_mode=WAL")
        # A receipt the desk handed out must survive a power cut, so every
        # commit waits for the disk rather than the OS page cache.
        self._db.execute("PRAGMA synchronous=FULL")
        with self.transaction():
            for table in _TABLES:
                self._db.execute(table)
            self._db.execute(
                "INSERT OR IGNORE INTO meta (name, value) VALUES ('schema', ?)",
                (str(SCHEMA_VERSION),),
            )
        schema = self.get("schema")
        if schema != str(SCHEMA_VERSION):
            raise ValueError(f"state: schema v{schema} unsupported")

    @property
    def path(self) -> Path:
        """The database file."""
        return self._path

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Group writes into one atomic commit; nested calls join the outer one.

        Raises:
            Exception: Whatever the body raised, after the outermost level
                rolled every write back.
        """
        with self._lock:
            outermost = self._depth == 0
            if outermost:
                self._db.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield
            except BaseException:
                self._depth -= 1
                # SQLite may have rolled back already (a full disk, an I/O
                # error); a second ROLLBACK would replace the real cause.
                if outermost and self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise
            self._depth -= 1
            if outermost:
                try:
                    self._db.execute("COMMIT")
                except BaseException:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                    raise

    def _all(self, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    def _write(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock:
            return self._db.execute(sql, params).rowcount

    def get(self, name: str) -> str | None:
        """Read one `meta` value, or None when unset."""
        rows = self._all("SELECT value FROM meta WHERE name = ?", (name,))
        return rows[0][0] if rows else None

    def put(self, name: str, value: str) -> None:
        """Set one `meta` value."""
        self._write(
            "INSERT INTO meta (name, value) VALUES (?, ?)"
            " ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            (name, value),
        )

    def consume(self, kind: str, key: str, expires_at: int) -> bool:
        """Spend a single-use key; True only the first time it is spent."""
        return (
            self._write(
                "INSERT OR IGNORE INTO used (kind, key, expires_at) VALUES (?, ?, ?)",
                (kind, key, expires_at),
            )
            == 1
        )

    def used(self, kind: str, key: str) -> bool:
        """Whether a single-use key has been spent (and not pruned)."""
        return bool(
            self._all("SELECT 1 FROM used WHERE kind = ? AND key = ?", (kind, key))
        )

    def prune(self, now: int) -> int:
        """Forget spent keys that expired before `now`; returns how many."""
        return self._write("DELETE FROM used WHERE expires_at < ?", (now,))

    def record(self, kind: str, key: str) -> str | None:
        """Read one record, or None when absent."""
        rows = self._all(
            "SELECT value FROM records WHERE kind = ? AND key = ?", (kind, key)
        )
        return rows[0][0] if rows else None

    def records(self, kind: str) -> list[tuple[str, str]]:
        """Every `(key, value)` of one kind, in first-insertion order."""
        rows = self._all(
            "SELECT key, value FROM records WHERE kind = ? ORDER BY rowid", (kind,)
        )
        return [(key, value) for key, value in rows]

    def put_record(self, kind: str, key: str, value: str) -> None:
        """Insert or update one record; an update keeps its original position."""
        self._write(
            "INSERT INTO records (kind, key, value) VALUES (?, ?, ?)"
            " ON CONFLICT (kind, key) DO UPDATE SET value = excluded.value",
            (kind, key, value),
        )

    def drop_record(self, kind: str, key: str) -> None:
        """Delete one record (no-op when absent)."""
        self._write("DELETE FROM records WHERE kind = ? AND key = ?", (kind, key))

    def entries(self) -> list[LogEntry]:
        """Every registry entry, in sequence order."""
        rows = self._all("SELECT seq, kind, body FROM entries ORDER BY seq")
        return [LogEntry(seq, kind, body) for seq, kind, body in rows]

    def add_entry(self, entry: LogEntry) -> None:
        """Append one registry entry; a repeated sequence number is an error."""
        self._write(
            "INSERT INTO entries (seq, kind, body) VALUES (?, ?, ?)",
            (entry.seq, entry.kind, entry.body),
        )

    def seals(self) -> list[dict[str, Any]]:
        """Every stored seal view, in order of the last sequence it covers."""
        rows = self._all("SELECT seal FROM seals ORDER BY seq_to")
        return [json.loads(seal) for (seal,) in rows]

    def add_seal(self, view: dict[str, Any]) -> None:
        """Store one seal view, keyed by the last sequence it covers."""
        self._write(
            "INSERT INTO seals (seq_to, seal) VALUES (?, ?)",
            (view["seq_to"], json.dumps(view, sort_keys=True, separators=(",", ":"))),
        )

    def revoked(self) -> list[int]:
        """Every revoked certificate index, ascending."""
        return [idx for (idx,) in self._all("SELECT idx FROM revoked ORDER BY idx")]

    def revoke(self, index: int) -> None:
        """Mark one certificate index revoked (idempotent)."""
        self._write("INSERT OR IGNORE INTO revoked (idx) VALUES (?)", (index,))

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._db.close()


def load_gate_key(path: Path) -> bytes:
    """Load the gate's 32-byte signing seed, creating it on first use.

    Args:
        path: The key file; created 0600 with fresh random bytes when missing.
            Temporary files a crashed earlier creation left beside it are
            removed.

    Returns:
        The 32 raw key bytes.

    Raises:
        ValueError: The file is a link, not this user's, readable by group or
            others, or not exactly 32 bytes long.
    """
    for stale in path.parent.glob(f".{path.name}.*.tmp"):
        stale.unlink(missing_ok=True)
    if not path.exists():
        _publish_key(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if path.is_symlink():
            raise ValueError("state: gate key must be a regular file") from exc
        raise
    try:
        _check_private(os.fstat(fd), "gate key", "600")
        data = os.read(fd, _KEY_LEN + 1)
    finally:
        os.close(fd)
    if len(data) != _KEY_LEN:
        raise ValueError("state: gate key must be 32 bytes")
    return data
