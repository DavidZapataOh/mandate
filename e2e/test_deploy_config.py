import os
import shlex
import subprocess
from pathlib import Path

from bank.credentials import BANK_KEY_NAMES, without_bank_key
from e2e.test_explorer_walkthrough import CLI, _free_port
from swarm.card import WEBHOOK_PATH

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"
SECRETS = (*BANK_KEY_NAMES, "BASETEN_API_KEY", "MODEL_API_KEY", "META_API_KEY")


def _unit_argv(key: str) -> list[str]:
    text = (DEPLOY / "mandate-console.service").read_text()
    line = next(x for x in text.splitlines() if x.startswith(f"{key}="))
    return shlex.split(line.removeprefix(f"{key}="))


def _flag(argv: list[str], name: str) -> str:
    return argv[argv.index(name) + 1]


def test_the_unit_publishes_through_the_local_proxy_only() -> None:
    argv = _unit_argv("ExecStart")
    assert argv[0] == "/opt/mandate/current/.venv/bin/mandate-console"
    assert {n: _flag(argv, n) for n in ("--host", "--port", "--local-port")} == {
        "--host": "127.0.0.1", "--port": "8766", "--local-port": "8767",
    }  # fmt: skip
    assert _flag(argv, "--trusted-proxy") == "127.0.0.1"
    # An installed package carries none of these: each points into the release tree.
    assert {
        n: _flag(argv, n) for n in ("--console-dir", "--webapp-dir", "--payees")
    } == {
        "--console-dir": "/opt/mandate/current/console/dist",
        "--webapp-dir": "/opt/mandate/current/webapp",
        "--payees": "/opt/mandate/current/demo/payees.json",
    }
    assert _flag(argv, "--public-host") == "${MANDATE_PUBLIC_HOST}"
    assert argv[-2:] == ["$MANDATE_RAIL_FLAGS", "$MANDATE_EXTRA_FLAGS"]
    assert _unit_argv("ExecStartPre") == [*argv, "--doctor"]


def test_no_secret_is_written_into_the_recipe() -> None:
    for name in ("mandate-console.service", "Caddyfile", "console.conf.example"):
        text = (DEPLOY / name).read_text()
        assert [s for s in SECRETS if s in text] == [], name


def test_the_proxy_never_reaches_the_local_port() -> None:
    text = (DEPLOY / "Caddyfile").read_text()
    upstreams = {
        line.split()[1] for line in text.splitlines()
        if line.strip().startswith("reverse_proxy")
    }  # fmt: skip
    assert upstreams == {"127.0.0.1:8766", "127.0.0.1:8768"}
    assert "8767" not in text
    assert f"handle {WEBHOOK_PATH} {{" in text


def test_the_proxy_refuses_a_host_other_than_the_tls_name() -> None:
    # Without it, a foreign Host on the same TLS connection gets an empty 200.
    lines = [x.strip() for x in (DEPLOY / "Caddyfile").read_text().splitlines()]
    assert lines[:5] == ["{", "servers {", "strict_sni_host on", "}", "}"]


def test_the_unit_flags_pass_the_doctor(tmp_path: Path) -> None:
    build = tmp_path / "dist"
    build.mkdir()
    (build / "index.html").write_text("<!doctype html>")
    root = str(Path(__file__).resolve().parent.parent)
    words = {
        "${MANDATE_PUBLIC_HOST}": ["desk.example.com"],
        "${MANDATE_STATE_DIR}": [str(tmp_path / "state")],
        "${MANDATE_HOLDERS}": ["0"],
        "$MANDATE_RAIL_FLAGS": ["--rail", "simulated"],
        "$MANDATE_EXTRA_FLAGS": [],
        "8766": [str(_free_port())],
        "8767": [str(_free_port())],
    }
    argv = [
        part.replace("/opt/mandate/current", root)
        for word in _unit_argv("ExecStartPre")[1:]
        for part in words.get(word, [word])
    ]
    argv[argv.index("--console-dir") + 1] = str(build)
    done = subprocess.run(  # noqa: S603
        [str(CLI), *argv], capture_output=True, text=True, timeout=60,
        env=without_bank_key(os.environ), check=False,
    )  # fmt: skip
    assert (done.returncode, done.stdout.splitlines()[-1]) == (0, "doctor: ready")
