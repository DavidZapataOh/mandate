import json
import subprocess
from collections import Counter
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parent.parent / "demo"
MANIFEST = DEMO / "swarm_manifest.json"
PROMPT = DEMO / "swarm_prompt.txt"
BOOKKEEPING = ("SessionStart", "SubagentStart", "subagent_spawn")


@pytest.mark.live
def test_live_governed_fanout(governed_repo):
    repo, state_dir = governed_repo
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
    listing = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    trees = [
        Path(x.split(" ", 1)[1])
        for x in listing.splitlines()
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
