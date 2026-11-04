"""Nimbus fixture CLI: the simulated prod-eu target of the live Muse Code deploy.

It appends each deploy or migration to `.nimbus/ledger.jsonl` under its working
directory, and every invocation with its caller to `.nimbus/calls.jsonl`; it
deploys nothing anywhere. It is stdlib only so the agent's shell can run it
with an isolated interpreter.
"""

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

LEDGER = Path(".nimbus") / "ledger.jsonl"
CALLS = Path(".nimbus") / "calls.jsonl"
USAGE = (
    "usage: nimbus deploy <artifact> <env> | nimbus migrate <migration> <env> "
    "| nimbus status <env>"
)
_SHELLS = frozenset({"bash", "zsh", "sh", "dash"})


def _read(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def _append(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(exist_ok=True)
    with path.open("a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def ledger(cwd: Path) -> list[dict[str, str]]:
    """The operations recorded under `cwd`, oldest first."""
    return _read(cwd / LEDGER)


def calls(cwd: Path) -> list[dict[str, Any]]:
    """Every invocation run under `cwd`, oldest first, with its caller."""
    return _read(cwd / CALLS)


def _parent() -> str:
    try:
        return subprocess.run(  # noqa: S603
            ["ps", "-o", "comm=", "-p", str(os.getppid())],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def shell_of(call: dict[str, Any], launcher: Path) -> str | None:
    """Which shell ran the launcher for one traced call, or None if unknown.

    Args:
        call: A record from `calls`.
        launcher: The installed launcher the shell found on its PATH.

    Returns:
        The parent shell's name; or "bash, zsh or sh" when the shell replaced
        itself with the launcher (a lone `-c` command) but exported `$_`, which
        those shells set to the path of the program they run; otherwise None.
    """
    name = Path(str(call.get("parent", ""))).name.lstrip("-")
    if name in _SHELLS:
        return name
    exported = str(call.get("exec_path", ""))
    if exported and os.path.realpath(exported) == os.path.realpath(launcher):
        return "bash, zsh or sh"
    return None


def main(argv: list[str], cwd: Path) -> int:
    """Run one Nimbus command against the simulated target under `cwd`.

    Returns:
        0 on success, 2 for any shape the CLI does not know.
    """
    _append(
        cwd / CALLS,
        {"argv": argv, "parent": _parent(), "exec_path": os.environ.get("_", "")},
    )
    match argv:
        case ["deploy", artifact, env]:
            _append(cwd / LEDGER, {"env": env, "op": "deploy", "target": artifact})
            print(f"Released {artifact} to {env} (simulated target)")
        case ["migrate", migration, env]:
            _append(cwd / LEDGER, {"env": env, "op": "migrate", "target": migration})
            print(f"Migrated {env} with {migration} (simulated target)")
        case ["status", env]:
            live = dict.fromkeys(
                r["target"]
                for r in ledger(cwd)
                if r["env"] == env and r["op"] == "deploy"
            )
            print(f"{env}: {', '.join(live) if live else 'nothing released'}")
        case _:
            print(USAGE, file=sys.stderr)
            return 2
    return 0


def install(bin_dir: Path) -> Path:
    """Write the `nimbus` launcher into `bin_dir` and return its path."""
    launcher = bin_dir / "nimbus"
    command = shlex.join([sys.executable, "-I", str(Path(__file__).resolve())])
    launcher.write_text(f'#!/bin/sh\nexec {command} "$@"\n')
    launcher.chmod(0o755)
    return launcher


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], Path.cwd()))
