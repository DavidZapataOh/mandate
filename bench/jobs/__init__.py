"""Every benchmarked path, in report order."""

from bench.job import Job
from bench.jobs.desk import DESK_JOBS
from bench.jobs.gate import GATE_JOBS

ALL_JOBS: tuple[Job, ...] = GATE_JOBS + DESK_JOBS
