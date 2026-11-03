"""In-process event hub: numbered, bounded, optionally recorded console lines."""

from __future__ import annotations

import secrets
import threading
from collections import deque
from dataclasses import replace
from typing import IO, TYPE_CHECKING

from swarm.console_line import ConsoleLine, console_line_json

if TYPE_CHECKING:
    from pathlib import Path


class EventHub:
    """Thread-safe store that numbers every published line from 1.

    Attributes:
        epoch: Random id of this hub; a restarted process gets a new one, so a
            client can tell that its remembered sequence numbers are stale.
    """

    def __init__(self, max_lines: int = 2000) -> None:
        """Create an empty hub.

        Args:
            max_lines: How many of the newest lines stay retrievable.
        """
        self.epoch = secrets.token_hex(8)
        self._lines: deque[ConsoleLine] = deque(maxlen=max_lines)
        self._lock = threading.Lock()
        self._seq = 0
        self._closed = False
        self._record: IO[str] | None = None

    @property
    def last_seq(self) -> int:
        """Sequence number of the newest line, 0 when nothing was published."""
        with self._lock:
            return self._seq

    @property
    def closed(self) -> bool:
        """Whether ``close`` was called."""
        with self._lock:
            return self._closed

    def publish(self, line: ConsoleLine) -> ConsoleLine:
        """Number a line, keep it, and write it to the recording if one is open.

        Args:
            line: The line to publish; its ``seq`` is ignored.

        Returns:
            The stamped line.
        """
        with self._lock:
            self._seq += 1
            stamped = replace(line, seq=self._seq)
            self._lines.append(stamped)
            if self._record is not None:
                try:
                    self._record.write(console_line_json(stamped) + "\n")
                    self._record.flush()
                except OSError:
                    self._drop_record()
            return stamped

    def since(self, seq: int) -> list[ConsoleLine]:
        """Return the retained lines numbered above ``seq``, oldest first."""
        with self._lock:
            if not self._lines:
                return []
            first = self._lines[0].seq
            start = max(seq + 1 - first, 0)
            return [self._lines[i] for i in range(start, len(self._lines))]

    def get(self, seq: int) -> ConsoleLine | None:
        """Return the retained line numbered ``seq``, or None."""
        with self._lock:
            if not self._lines:
                return None
            index = seq - self._lines[0].seq
            if 0 <= index < len(self._lines):
                return self._lines[index]
            return None

    @property
    def recording(self) -> bool:
        """Whether lines are currently being written to a recording."""
        with self._lock:
            return self._record is not None

    def record(self, path: Path) -> None:
        """Append every line published from now on to ``path`` as JSONL.

        A previous recording is closed.

        Raises:
            ValueError: ``hub closed`` after ``close``.
        """
        with self._lock:
            if self._closed:
                raise ValueError("hub closed")
            handle = path.open("a", encoding="utf-8")
            self._drop_record()
            self._record = handle

    def _drop_record(self) -> None:
        # A failing recorder must never take the live feed down with it.
        handle, self._record = self._record, None
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass

    def close(self) -> None:
        """Mark the hub closed and stop recording; later publishes are kept."""
        with self._lock:
            self._closed = True
            self._drop_record()
