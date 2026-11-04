"""Owner-run live measurements: recorded with their date, never gated."""

import json
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from bench.runner import percentile
from gate.state import iso_utc


@dataclass(frozen=True)
class LiveResult:
    """Wall times of one live job against a real provider.

    Args:
        name: Job name, also the file name under the live directory.
        provider: Who answered, e.g. ``increase``.
        measured_at: UTC time the job ran, ``YYYY-MM-DDTHH:MM:SSZ``.
        samples: Calls timed.
        p50_ms: Median wall time of one call.
        p95_ms: 95th percentile wall time of one call.
        max_ms: Slowest call.
        note: What one call includes.
    """

    name: str
    provider: str
    measured_at: str
    samples: int
    p50_ms: float
    p95_ms: float
    max_ms: float
    note: str


def time_live(
    name: str,
    provider: str,
    note: str,
    fn: Callable[[], object],
    n: int,
    now: Callable[[], float] = time.time,
    timer: Callable[[], float] = time.perf_counter,
) -> LiveResult:
    """Call ``fn`` ``n`` times with no warmup and record each wall time.

    Returns:
        The statistics, each rounded to 0.1 ms, dated by ``now``.
    """
    measured_at = iso_utc(int(now()))
    samples: list[float] = []
    for _ in range(n):
        start = timer()
        fn()
        samples.append((timer() - start) * 1000.0)
    ordered = sorted(samples)
    return LiveResult(
        name=name,
        provider=provider,
        measured_at=measured_at,
        samples=len(ordered),
        p50_ms=round(percentile(ordered, 50), 1),
        p95_ms=round(percentile(ordered, 95), 1),
        max_ms=round(ordered[-1], 1),
        note=note,
    )


def save_live(result: LiveResult, live_dir: Path) -> Path:
    """Write ``<live_dir>/<name>.json``, creating the directory.

    Returns:
        The written path.
    """
    live_dir.mkdir(parents=True, exist_ok=True)
    path = live_dir / f"{result.name}.json"
    path.write_text(json.dumps(asdict(result), indent=2) + "\n")
    return path


_FIELDS = tuple(f.name for f in fields(LiveResult))


def load_live(live_dir: Path) -> tuple[LiveResult, ...]:
    """Every recorded live result, sorted by file name; () without a directory.

    Raises:
        ValueError: A file that is not JSON or does not hold a LiveResult.
    """
    if not live_dir.is_dir():
        return ()
    out: list[LiveResult] = []
    for path in sorted(live_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            if not isinstance(data, dict) or tuple(data) != _FIELDS:
                raise ValueError(path.name)
            out.append(LiveResult(**data))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"live: {path.name} unreadable") from exc
    return tuple(out)
