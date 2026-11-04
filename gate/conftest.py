"""Test-only calendars, block sources and recorded OpenTimestamps answers."""

import base64
import json
import urllib.error
from pathlib import Path
from typing import Any

from opentimestamps.calendar import CommitmentNotFoundError
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.timestamp import Timestamp

from gate.anchor_public import AGGREGATORS, AnchorError, Calendar

OTS_FILE = (
    Path(__file__).resolve().parent.parent
    / "console/src/explorer/__fixtures__/ots.json"
)
OTS: dict[str, Any] = json.loads(OTS_FILE.read_text()) if OTS_FILE.exists() else {}


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


class RecordedAggregator:
    """An aggregator that replays one recorded answer, or is unreachable."""

    def __init__(self, answer: bytes | None) -> None:
        self.answer = answer
        self.submitted: list[bytes] = []

    def submit(self, digest: bytes, timeout: float | None = None) -> Timestamp:
        self.submitted.append(digest)
        if self.answer is None:
            raise urllib.error.URLError("unreachable")
        # A recorded answer's operations are relative to its message.
        return Timestamp.deserialize(BytesDeserializationContext(self.answer), digest)


def recorded_aggregators(up: int = 4) -> list[RecordedAggregator]:
    """The recorded aggregators in `AGGREGATORS` order; the last `4 - up` down."""
    answers = [unb64(OTS["aggregators"][url]) for url in AGGREGATORS]
    return [
        RecordedAggregator(answer if i < up else None)
        for i, answer in enumerate(answers)
    ]


class _RecordedCalendar:
    """One calendar URI of `RecordedCalendars`; it only answers `get_timestamp`."""

    def __init__(self, owner: "RecordedCalendars", uri: str) -> None:
        self.owner = owner
        self.uri = uri

    def submit(self, digest: bytes, timeout: float | None = None) -> Timestamp:
        raise urllib.error.URLError("a recorded calendar takes no submissions")

    def get_timestamp(
        self, commitment: bytes, timeout: float | None = None
    ) -> Timestamp:
        self.owner.asked.append(self.uri)
        recorded = self.owner.answers.get(commitment.hex())
        if recorded is None:
            raise CommitmentNotFoundError("Pending confirmation in Bitcoin blockchain")
        ctx = BytesDeserializationContext(unb64(recorded["answer"]))
        return Timestamp.deserialize(ctx, commitment)


class RecordedCalendars:
    """Calendars that replay recorded `get_timestamp` answers by commitment."""

    def __init__(self, answers: dict[str, dict[str, str]]) -> None:
        self.answers = answers
        self.asked: list[str] = []

    def for_uri(self, uri: str) -> Calendar:
        return _RecordedCalendar(self, uri)


class RecordedHeaders:
    """A header source that replays recorded headers by height."""

    def __init__(self, headers: dict[int, bytes]) -> None:
        self.headers = headers
        self.asked: list[int] = []

    def header(self, height: int) -> bytes:
        self.asked.append(height)
        if height not in self.headers:
            raise AnchorError("anchor: header source unavailable")
        return self.headers[height]
