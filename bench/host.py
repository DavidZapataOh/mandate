"""The machine a benchmark ran on, as the report names it."""

import os
import platform
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _run(argv: list[str]) -> str | None:
    try:
        done = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            cwd=_ROOT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = done.stdout.strip()
    return out if done.returncode == 0 and out else None


def _cpu() -> str:
    if sys.platform == "darwin":
        name = _run(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"])
        if name:
            return name
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "model name" and value.strip():
                return value.strip()
    except OSError:
        pass
    return platform.processor() or "unknown CPU"


def host() -> dict[str, str]:
    """CPU, core count, OS, Python version and commit of this checkout."""
    return {
        "cpu": _cpu(),
        "cores": str(os.cpu_count() or 0),
        "os": platform.platform(terse=True),
        "python": platform.python_version(),
        "commit": _run(["git", "describe", "--always", "--dirty"]) or "unknown",
    }
