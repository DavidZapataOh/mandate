import json
import subprocess
import sys
from pathlib import Path

import pytest

from swarm.hook import main
from swarm.hookio import ChildStarted
from swarm.state import (
    SwarmManifest,
    bind_lead,
    new_state,
    request_spawn,
    save_state,
    start_child,
)
from swarm.test_hookio import CHILD_START, EDIT, SESSION_START
from swarm.test_state import MANIFEST

NOW = 1800000000
HOOK = Path(sys.executable).parent / "mandate-hook"


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    return root


@pytest.fixture
def state_dir(tmp_path):
    path = tmp_path / "authority"
    path.mkdir()
    (path / "swarm.json").write_text(json.dumps(MANIFEST))
    save_state(new_state(), path / "state.json")
    return path


@pytest.fixture
def send(repo, state_dir):
    def _send(payload, nonce="n" * 32):
        cwd = payload.get("cwd", "")
        if cwd == "/repo" or cwd.startswith("/repo/"):
            payload = dict(payload, cwd=str(repo) + cwd[len("/repo") :])
        return main(json.dumps(payload), NOW, nonce, state_dir, repo)

    return _send


@pytest.fixture
def journal(state_dir):
    def _journal():
        path = state_dir / "journal.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    return _journal


def _spawn(role="docs", isolated=True):
    return dict(
        EDIT,
        session_id="lead-1",
        cwd="/repo",
        tool_name="subagent_spawn",
        tool_input={
            "command_id": "c1",
            "objective": "Update the README",
            "role": role,
            "worktree_isolation": isolated,
        },
    )


def _bound_child(send):
    assert send(SESSION_START) == (0, "")
    assert send(_spawn()) == (0, "")
    assert send(CHILD_START) == (0, "")


def _reason(stdout):
    return json.loads(stdout)["hookSpecificOutput"]["permissionDecisionReason"]


def test_in_scope_edit_passes(send, journal):
    _bound_child(send)
    assert send(EDIT) == (0, "")
    last = journal()[-1]
    assert (last["agent"], last["tool"]) == ("child-1", "edit_file")
    assert last["event"]["verdict"] == "MET"


def test_out_of_scope_edit_denied(send, journal):
    _bound_child(send)
    call = dict(EDIT, tool_input=dict(EDIT["tool_input"], path="deploy.env"))
    code, out = send(call)
    assert code == 0
    assert _reason(out) == "scope: target outside delegation"
    assert journal()[-1]["event"]["verdict"] == "NOT_MET"


def test_unbound_session_denied(send):
    assert send(SESSION_START) == (0, "")
    _, out = send(EDIT)
    assert _reason(out) == "scope: agent has no delegation"


def test_spawn_without_isolation_denied(send):
    assert send(SESSION_START) == (0, "")
    _, out = send(_spawn(isolated=False))
    assert _reason(out) == "spawn: worktree isolation required"


def test_pass_tools_unjournaled(send, journal):
    _bound_child(send)
    before = len(journal())
    read = dict(EDIT, tool_name="read_file", tool_input={"path": "deploy.env"})
    assert send(read) == (0, "")
    assert len(journal()) == before


def test_unclassified_tool_not_checkable(send, journal):
    _bound_child(send)
    _, out = send(dict(EDIT, tool_name="web_fetch", tool_input={}))
    assert _reason(out) == "unclassified tool: web_fetch"
    assert journal()[-1]["event"]["verdict"] == "NOT_CHECKABLE"


def test_malformed_stdin_fails_closed(repo, state_dir):
    code, out = main("not json", NOW, "n" * 32, state_dir, repo)
    assert code == 0
    assert _reason(out) == "malformed: hook payload"


def test_no_state_fails_closed(send, state_dir):
    (state_dir / "state.json").unlink()
    _, out = send(EDIT)
    assert _reason(out) == "malformed: no mandate state"


def test_journal_event_is_v1_decision(send, journal):
    _bound_child(send)
    send(EDIT, nonce="e" * 32)
    event = journal()[-1]["event"]
    assert (event["v"], event["id"], event["policy"]) == (1, "evt:" + "e" * 32, "swarm")


def test_corrupt_state_denies(send, state_dir):
    (state_dir / "state.json").write_text("{")
    code, out = send(EDIT)
    assert code == 0
    assert _reason(out) == "malformed: mandate error"


def test_invalid_manifest_denies(send, state_dir):
    broken = dict(MANIFEST, roles={})
    (state_dir / "swarm.json").write_text(json.dumps(broken))
    code, out = send(EDIT)
    assert code == 0
    assert _reason(out) == "malformed: mandate error"


def test_unwritable_journal_still_denies(send, journal, state_dir):
    _bound_child(send)
    (state_dir / "journal.jsonl").unlink()
    (state_dir / "journal.jsonl").mkdir()
    call = dict(EDIT, tool_input=dict(EDIT["tool_input"], path="deploy.env"))
    code, out = send(call)
    assert code == 0
    assert _reason(out) == "scope: target outside delegation"


def test_deep_json_denies(repo, state_dir):
    deep = '{"hook_event_name":"PreToolUse","x":' + "[" * 5000 + "]" * 5000 + "}"
    code, out = main(deep, NOW, "n" * 32, state_dir, repo)
    assert code == 0
    assert _reason(out).startswith("malformed:")


def test_state_lock_held_during_decision(send, state_dir, monkeypatch):
    import fcntl

    import swarm.hook as hook

    probes = []
    real = hook.load_state

    def probe(path):
        with open(state_dir / "state.lock", "w") as other:
            try:
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                probes.append("acquired")
            except BlockingIOError:
                probes.append("blocked")
        return real(path)

    monkeypatch.setattr(hook, "load_state", probe)
    assert send(SESSION_START) == (0, "")
    assert probes == ["blocked"]


def _plant_wide_state(directory):
    wide = json.loads(json.dumps(MANIFEST))
    wide["roles"]["docs"]["atoms"].append("file:deploy.env")
    wide["roles"]["lead"]["atoms"].append("file:deploy.env")
    wide["root"]["atoms"].append("cmd:git")
    directory.mkdir(parents=True)
    (directory / "swarm.json").write_text(json.dumps(wide))
    manifest = SwarmManifest.load(directory / "swarm.json")
    state, _ = bind_lead(new_state(), manifest, "lead-1", NOW)
    state, _, _ = request_spawn(state, manifest, "lead-1", "docs", True, NOW)
    child = ChildStarted(CHILD_START["subagent_id"], "child-1")
    state, _ = start_child(state, manifest, child, NOW)
    save_state(state, directory / "state.json")


def test_planted_worktree_state_is_ignored(send, journal, repo):
    _bound_child(send)
    tree = repo / ".muse" / "worktrees" / "x"
    _plant_wide_state(tree / ".mandate")
    call = dict(
        EDIT,
        cwd=str(tree),
        tool_input=dict(EDIT["tool_input"], path="deploy.env"),
    )
    _, out = send(call)
    assert _reason(out) == "scope: target outside delegation"
    assert journal()[-1]["event"]["verdict"] == "NOT_MET"
    assert not (tree / ".mandate" / "journal.jsonl").exists()


@pytest.mark.parametrize(
    "cwd", ["/elsewhere", "/repo/payments", "/repo/.muse/worktrees", "/repo/../x"]
)
def test_cwd_outside_repo_denied(send, journal, cwd):
    _bound_child(send)
    _, out = send(dict(EDIT, cwd=cwd))
    assert _reason(out) == "scope: cwd outside governed repo"
    assert journal()[-1]["event"]["verdict"] == "NOT_MET"


def test_session_start_outside_repo_ignored(send, journal, state_dir):
    assert send(dict(SESSION_START, cwd="/elsewhere")) == (0, "")
    last = journal()[-1]
    assert (last["tool"], last["event"]["reason"]) == (
        "SessionStart",
        "scope: cwd outside governed repo",
    )
    assert json.loads((state_dir / "state.json").read_text())["lead"] is None


def test_child_outside_worktree_denied(send):
    _bound_child(send)
    _, out = send(dict(EDIT, cwd="/repo"))
    assert _reason(out) == "scope: child outside its worktree"


def test_observer_pass_tool_from_root_passes(send, journal):
    _bound_child(send)
    before = len(journal())
    call = dict(
        EDIT,
        session_id="skill-reminder-session",
        cwd="/repo",
        tool_name="submit_reminder_decision",
        tool_input={"decision": "skip"},
    )
    assert send(call) == (0, "")
    assert len(journal()) == before


def test_lead_at_root_is_governed(send, journal):
    assert send(SESSION_START) == (0, "")
    call = dict(EDIT, session_id="lead-1", cwd="/repo")
    assert send(call) == (0, "")
    assert journal()[-1]["event"]["verdict"] == "MET"


@pytest.mark.parametrize("path", [".mandate/swarm.json", ".muse/hooks.json"])
def test_protected_paths_denied(send, path):
    assert send(SESSION_START) == (0, "")
    call = dict(EDIT, session_id="lead-1", cwd="/repo")
    call["tool_input"] = dict(EDIT["tool_input"], path=path)
    _, out = send(call)
    assert _reason(out) == "scope: protected path"


@pytest.mark.parametrize("path", ["../../x", "/etc/passwd"])
def test_pass_tool_path_escape_denied(send, journal, path):
    _bound_child(send)
    _, out = send(dict(EDIT, tool_name="read_file", tool_input={"path": path}))
    assert _reason(out) == "scope: path escapes worktree"
    assert journal()[-1]["tool"] == "read_file"


def test_journal_records_targets_and_tool_use_id(send, journal):
    _bound_child(send)
    send(EDIT)
    lines = journal()
    spawn, start, edit = lines[-3:]
    assert spawn["targets"] == ["role:docs"]
    assert spawn["tool_use_id"] == "call_1"
    assert start["targets"] == []
    assert "tool_use_id" not in start
    assert edit["targets"] == ["file:README.md"]
    assert edit["tool_use_id"] == "call_1"


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--state-dir", "authority", "--root", "/"],
        ["--state-dir", "/nonexistent-mandate", "--root", "/"],
        ["--state-dir", "/", "--root", "relative"],
    ],
)
def test_cli_requires_pinned_dirs(args):
    run = subprocess.run(  # noqa: S603
        [str(HOOK), *args],
        input=json.dumps(EDIT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0
    assert _reason(run.stdout) == "malformed: mandate error"


@pytest.mark.parametrize("inside", ["", "authority", "a/../authority"])
def test_cli_rejects_state_dir_inside_root(repo, inside):
    state_dir = repo / inside
    (repo / "authority").mkdir(exist_ok=True)
    (repo / "authority" / "swarm.json").write_text(json.dumps(MANIFEST))
    save_state(new_state(), repo / "authority" / "state.json")
    (repo / "a").mkdir(exist_ok=True)
    payload = dict(EDIT, cwd=str(repo / ".muse" / "worktrees" / "x"))
    run = subprocess.run(  # noqa: S603
        [str(HOOK), "--state-dir", str(state_dir), "--root", str(repo)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0
    assert _reason(run.stdout) == "malformed: mandate error"


def test_cli_with_pinned_dirs_decides(repo, state_dir):
    payload = dict(EDIT, cwd=str(repo / ".muse" / "worktrees" / "x"))
    run = subprocess.run(  # noqa: S603
        [str(HOOK), "--state-dir", str(state_dir), "--root", str(repo)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0
    assert _reason(run.stdout) == "scope: agent has no delegation"
