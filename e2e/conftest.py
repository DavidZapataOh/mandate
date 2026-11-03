import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from swarm.server import build_server
from swarm.state import new_state, save_state

DEMO = Path(__file__).resolve().parent.parent / "demo"
TEMPLATE = DEMO / "swarm_repo"
MANIFEST = DEMO / "swarm_manifest.json"
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


@pytest.fixture
def governed_repo(tmp_path):
    if shutil.which("muse") is None or not HOOK.exists():
        pytest.skip("live: needs muse on PATH and mandate-hook installed")
    repo = (tmp_path / "repo").resolve()
    state_dir = (tmp_path / "authority").resolve()
    shutil.copytree(
        TEMPLATE, repo, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache")
    )
    if (repo / ".mandate").exists():
        pytest.fail("template must not ship .mandate")
    state_dir.mkdir()
    shutil.copy(MANIFEST, state_dir / "swarm.json")
    save_state(new_state(), state_dir / "state.json")
    _hooks(repo, state_dir)
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    return repo, state_dir


@pytest.fixture
def pairing_token():
    return secrets.token_urlsafe(16)


@pytest.fixture
def running_desk(make_desk, pairing_token):
    desk, _ = make_desk(register=False)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    app = build_server(desk, pairing_token).streamable_http_app()
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, daemon=True
    )
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("desk server did not start")
        time.sleep(0.02)
    yield desk, f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(5)
