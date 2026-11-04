"""Named benchmark jobs: what one path measures and how it is set up."""

from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from bench.runner import BenchResult, run_rounds

IN_PROCESS = "in process"
LOCAL_DISK = "local disk"
LABELS: dict[str, str] = {
    IN_PROCESS: "In process: one thread, fixed inputs",
    LOCAL_DISK: "Local disk: in process, SQLite state store, synchronous=FULL",
}

Timed = Callable[[], dict[str, int] | None]


@dataclass(frozen=True)
class Job:
    """One measured path.

    Args:
        name: Budget section name, e.g. ``gate.shim.decide``.
        label: What the number includes; a key of ``LABELS``.
        setup: Builds the timed call in a scratch directory; resources it
            opens are closed through the exit stack after timing.
        n: Timed calls per round.
        warmup: Untimed calls before the first round.
        rounds: Timed rounds; each statistic is the median of theirs.
    """

    name: str
    label: str
    setup: Callable[[Path, ExitStack], Timed]
    n: int
    warmup: int
    rounds: int = 3


def measure(job: Job, scratch: Path) -> BenchResult:
    """Set up one job in ``scratch``, time it, then release what it opened.

    Returns:
        The combined result of the job's rounds.
    """
    scratch.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        timed = job.setup(scratch, stack)
        return run_rounds(job.name, timed, job.n, job.warmup, job.rounds)
