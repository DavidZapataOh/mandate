import os
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from demo.nimbus_cli import install
from e2e.poisoned_mcp import build_poisoned_server
from swarm.server import build_server
from swarm.state import new_state, save_state

DEMO = Path(__file__).resolve().parent.parent / "demo"
TEMPLATE = DEMO / "swarm_repo"
MANIFEST = DEMO / "swarm_manifest.json"
NIMBUS_TEMPLATE = DEMO / "nimbus_repo"
NIMBUS_MANIFEST = DEMO / "nimbus_manifest.json"
HOOK = Path(sys.executable).parent / "mandate-hook"


def _git(repo, *args):
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _hooks(repo, state_dir):
    tmpl = repo / ".muse" / "hooks.json.tmpl"
    text = tmpl.read_text()
    for key, value in (("@HOOK@", HOOK), ("@STATE@", state_dir), ("@ROOT@", repo)):
        text = text.replace(key, shlex.quote(str(value)))
    (repo / ".muse" / "hooks.json").write_text(text)
    tmpl.unlink()


def prepare_governed(base: Path, template: Path, manifest: Path) -> tuple[Path, Path]:
    """Copy a template repo under `base` and pin its hook to a state dir beside it."""
    repo = (base / "repo").resolve()
    state_dir = (base / "authority").resolve()
    shutil.copytree(
        template, repo, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache")
    )
    if (repo / ".mandate").exists():
        pytest.fail("template must not ship .mandate")
    state_dir.mkdir()
    shutil.copy(manifest, state_dir / "swarm.json")
    save_state(new_state(), state_dir / "state.json")
    _hooks(repo, state_dir)
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    return repo, state_dir


def _needs_muse():
    if shutil.which("muse") is None or not HOOK.exists():
        pytest.skip("live: needs muse on PATH and mandate-hook installed")


@pytest.fixture
def governed_repo(tmp_path):
    _needs_muse()
    return prepare_governed(tmp_path, TEMPLATE, MANIFEST)


@pytest.fixture
def nimbus_repo(tmp_path):
    _needs_muse()
    base = Path(os.environ.get("MANDATE_FLUJO_F_DIR") or tmp_path)
    if base.exists() and any(base.iterdir()):
        pytest.fail(f"MANDATE_FLUJO_F_DIR must be empty: {base}")
    base.mkdir(parents=True, exist_ok=True)
    repo, state_dir = prepare_governed(base, NIMBUS_TEMPLATE, NIMBUS_MANIFEST)
    bin_dir = base / "bin"
    bin_dir.mkdir()
    install(bin_dir)
    return repo, state_dir, bin_dir


@contextmanager
def serve(app: Any) -> Iterator[str]:
    """Run an ASGI app on a free local port for the duration of the block."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, daemon=True
    )
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("server did not start")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(5)


@pytest.fixture
def poisoned_mcp():
    calls: list[dict[str, Any]] = []
    with serve(build_poisoned_server(calls).streamable_http_app()) as url:
        yield f"{url}/mcp", calls


@pytest.fixture
def pairing_token():
    return secrets.token_urlsafe(16)


@pytest.fixture
def running_desk(make_desk, pairing_token):
    desk, _ = make_desk(register=False)
    with serve(build_server(desk, pairing_token).streamable_http_app()) as url:
        yield desk, url
