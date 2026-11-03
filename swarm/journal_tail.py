"""Follow the hook journal and publish its records to the event hub."""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING

from swarm.console_line import read_hook_record

if TYPE_CHECKING:
    from pathlib import Path

    from swarm.hub import EventHub

_JOIN_TIMEOUT_S = 5
MAX_PARTIAL = 1 << 20
READ_CHUNK = 1 << 20


class JournalTail:
    """Poll an append-only JSONL journal and publish each complete record.

    Three tolerance rules keep a live demo from stalling: a journal that does
    not exist yet is waited for; a trailing record without its newline waits
    for the rest; a journal that was truncated or replaced is read again from
    its start. Only hook records are published; anything else, including a
    console line written into the journal, is counted in ``skipped``. Each
    poll reads at most ``READ_CHUNK`` bytes, so a large journal is published
    over several polls.

    Attributes:
        skipped: Records dropped because they were not hook records or too long.
        errors: Polling passes that failed on the thread and were retried.
    """

    def __init__(self, path: Path, hub: EventHub, poll_s: float = 0.2) -> None:
        """Create a tail positioned at the start of the journal.

        Args:
            path: Journal file; it may not exist yet.
            hub: Hub that receives the lines.
            poll_s: Seconds between reads while running on its thread.
        """
        self._path = path
        self._hub = hub
        self._poll_s = poll_s
        self._offset = 0
        self._inode: int | None = None
        self._partial = b""
        self._discarding = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.skipped = 0
        self.errors = 0

    def poll(self) -> int:
        """Read what was appended since the last call.

        Returns:
            How many lines were published.
        """
        try:
            with self._path.open("rb") as handle:
                stat = os.fstat(handle.fileno())
                if stat.st_ino != self._inode or stat.st_size < self._offset:
                    self._inode = stat.st_ino
                    self._offset = 0
                    self._partial = b""
                    self._discarding = False
                handle.seek(self._offset)
                data = handle.read(READ_CHUNK)
        except FileNotFoundError:
            return 0
        self._offset += len(data)
        *records, self._partial = (self._partial + data).split(b"\n")
        published = 0
        for record in records:
            if self._discarding:
                self._discarding = False
                continue
            published += self._publish(record)
        if len(self._partial) > MAX_PARTIAL:
            self._partial = b""
            self._discarding = True
            self.skipped += 1
        return published

    def _publish(self, record: bytes) -> int:
        if not record.strip():
            return 0
        try:
            line = read_hook_record(record.decode("utf-8"))
        except ValueError:
            self.skipped += 1
            return 0
        self._hub.publish(line)
        return 1

    def start(self) -> None:
        """Poll on a daemon thread until ``stop``."""
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the polling thread and wait for it."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(_JOIN_TIMEOUT_S)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll()
            except Exception:
                self.errors += 1
            self._stop.wait(self._poll_s)
