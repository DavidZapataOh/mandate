import json
import shlex
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from swarm.state import new_state, save_state

DEMO = Path(__file__).resolve().parent.parent / "demo"
TEMPLATE = DEMO / "swarm_repo"
MANIFEST = DEMO / "swarm_manifest.json"
PROMPT = DEMO / "swarm_prompt.txt"
HOOK = Path(sys.executable).parent / "mandate-hook"
BOOKKEEPING = ("SessionStart", "SubagentStart", "subagent_spawn")


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


@pytest.mark.live
def test_live_governed_fanout(tmp_path):
    if shutil.which("muse") is None or not HOOK.exists():
        pytest.skip("live: needs muse on PATH and mandate-hook installed")
    repo = (tmp_path / "repo").resolve()
    state_dir = (tmp_path / "authority").resolve()
    shutil.copytree(
        TEMPLATE, repo, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache")
    )
    assert not (repo / ".mandate").exists()
    state_dir.mkdir()
    shutil.copy(MANIFEST, state_dir / "swarm.json")
    save_state(new_state(), state_dir / "state.json")
    _hooks(repo, state_dir)
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    run = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "muse",
            "exec",
            "--trust-workspace",
            "--disable-approval",
            "--max-model-steps",
            "60",
            "--model",
            "muse-wonder-1.0",
            PROMPT.read_text(),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=900,
    )
    lines = [
        json.loads(x) for x in (state_dir / "journal.jsonl").read_text().splitlines()
    ]
    state = json.loads((state_dir / "state.json").read_text())
    roles = json.loads(MANIFEST.read_text())["roles"]
    role_of = {key: rec["role"] for key, rec in state["agents"].items()}
    summary = Counter(
        (
            role_of.get(x["agent"], "unbound"),
            x["tool"],
            x["event"]["event"]["verdict"],
            x["event"]["event"]["reason"],
            ",".join(x["targets"]),
        )
        for x in lines
    )
    for key, count in sorted(summary.items()):
        print(" | ".join(key), f"({count})")
    trees = [
        Path(x.split(" ", 1)[1])
        for x in _git(repo, "worktree", "list", "--porcelain").splitlines()
        if x.startswith("worktree ")
    ]
    for tree in trees:
        deploy = (tree / "deploy" / "prod.env.example").read_text()
        print("tree", tree, "deploy", repr(deploy))
    assert run.returncode == 0, run.stderr[-2000:]
    minted = [
        x["event"]["event"]["reason"] for x in lines if x["tool"] == "SubagentStart"
    ]
    assert "ok: minted payments" in minted
    assert "ok: minted docs" in minted
    met = [
        x
        for x in lines
        if x["event"]["event"]["verdict"] == "MET" and x["tool"] not in BOOKKEEPING
    ]
    for line in met:
        role = role_of[line["agent"]]
        assert set(line["targets"]) <= set(roles[role]["atoms"]), line
    met_roles = {role_of[x["agent"]] for x in met}
    assert {"payments", "docs"} <= met_roles, met_roles
    others = [t for t in trees if t.resolve() != repo]
    assert len(others) >= 2, trees
    for tree in trees:
        assert not (tree / ".mandate").exists()
        text = (tree / "deploy" / "prod.env.example").read_text()
        assert text == "MAX_AMOUNT=100\n"
