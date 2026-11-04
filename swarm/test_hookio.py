import json

import pytest

from swarm.hookio import (
    ChildStarted,
    Kind,
    ScopeError,
    SessionStarted,
    ToolCall,
    classify,
    deny_output,
    is_observer,
    parse_event,
    targets_for,
)

WT = "/repo/.muse/worktrees/subagent-v2-1"
SESSION_START = {
    "hook_event_name": "SessionStart",
    "source": "startup",
    "session_id": "lead-1",
    "cwd": "/repo",
    "transcript_path": None,
    "model": "muse-wonder-1.0",
    "permission_mode": "bypassPermissions",
    "model_provider": "meta",
}
CHILD_START = {
    "hook_event_name": "SubagentStart",
    "subagent_id": "01a19f76-4b91-7342-b01f-75765e69d6bb",
    "child_session_id": "child-1",
    "session_id": "child-1",
    "turn_id": "child-1",
    "cwd": "/repo",
    "transcript_path": None,
    "model": "muse-spark-1.3",
    "permission_mode": "bypassPermissions",
    "model_provider": "meta",
}
EDIT = {
    "hook_event_name": "PreToolUse",
    "tool_name": "edit_file",
    "tool_input": {"find": "# Probe", "path": "README.md", "replace": "# Probe\nHi"},
    "tool_use_id": "call_1",
    "session_id": "child-1",
    "turn_id": "child-1",
    "cwd": WT,
    "transcript_path": None,
    "model": "muse-spark-1.3",
    "permission_mode": "bypassPermissions",
    "model_provider": "meta",
}


def _call(tool, tool_input):
    return ToolCall(
        session_id="child-1",
        tool=tool,
        tool_input=tool_input,
        cwd=WT,
        model="muse-spark-1.3",
        tool_use_id="call_1",
    )


def test_parse_captured_payloads():
    assert parse_event(SESSION_START) == SessionStarted("lead-1", "/repo")
    assert parse_event(CHILD_START) == ChildStarted(
        "01a19f76-4b91-7342-b01f-75765e69d6bb", "child-1"
    )
    assert parse_event(EDIT) == _call("edit_file", EDIT["tool_input"])


@pytest.mark.parametrize(
    "payload",
    [{}, [], "x", {"hook_event_name": "PreToolUse"}, dict(EDIT, tool_input="x")],
)
def test_parse_rejects_malformed(payload):
    with pytest.raises(ValueError, match="malformed hook payload"):
        parse_event(payload)


def test_observers_are_named_children_are_uuids():
    assert is_observer(ChildStarted("skill-reminder", "s-1")) is True
    assert is_observer(ChildStarted("verify-reminder", "s-2")) is True
    assert is_observer(parse_event(CHILD_START)) is False


def test_deny_output_matches_muse_contract():
    assert json.loads(deny_output("scope: x")) == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "scope: x",
        }
    }
    with pytest.raises(ValueError, match="deny reason required"):
        deny_output("")


@pytest.mark.parametrize(
    ("tool", "kind"),
    [
        ("read_file", Kind.PASS),
        ("search", Kind.PASS),
        ("subagent_read_result", Kind.PASS),
        ("submit_reminder_decision", Kind.PASS),
        ("subagent_spawn", Kind.SPAWN),
        ("edit_file", Kind.GOVERNED),
        ("write_file", Kind.GOVERNED),
        ("delete_file", Kind.GOVERNED),
        ("bash", Kind.GOVERNED),
        ("exec_command", Kind.GOVERNED),
        ("apply_patch", Kind.DENY),
        ("web_fetch", Kind.DENY),
    ],
)
def test_classify(tool, kind):
    assert classify(tool) is kind


def test_targets_for_file_and_shell():
    assert targets_for(_call("edit_file", {"path": "./payments//handler.py"})) == (
        "file:payments/handler.py",
    )
    cmd = {"command": "ls -la && pytest -q payments | cat; git status"}
    assert targets_for(_call("bash", cmd)) == (
        "cmd:ls",
        "cmd:pytest",
        "cmd:cat",
        "cmd:git",
    )


@pytest.mark.parametrize(
    "path", ["../deploy/prod.env.example", "/etc/hosts", "a/../../b", ".."]
)
def test_targets_reject_path_escape(path):
    with pytest.raises(ScopeError, match="scope: path escapes worktree"):
        targets_for(_call("write_file", {"path": path, "content": "x"}))


@pytest.mark.parametrize(
    "command",
    [
        "echo x > deploy/prod.env.example",
        "cat $(echo secret)",
        "ls `pwd`",
        "ls\nrm -rf x",
        "ls\r\nrm x",
        "ls & rm x",
        "ls &&& rm x",
        "cat <(rm x)",
        "echo ${HOME}",
        "ls $HOME",
        "(rm x)",
        "{ rm x; }",
        "ls\x00rm",
    ],
)
def test_targets_reject_shell_redirection(command):
    with pytest.raises(ScopeError, match="scope: shell redirection or substitution"):
        targets_for(_call("bash", {"command": command}))


def test_targets_reject_apply_patch_and_missing_target():
    with pytest.raises(ScopeError, match="scope: apply_patch not governed"):
        targets_for(_call("apply_patch", {"patch": "..."}))
    with pytest.raises(ScopeError, match="scope: missing tool target"):
        targets_for(_call("edit_file", {}))


def test_targets_reject_nul_in_path():
    with pytest.raises(ScopeError, match="scope: path escapes worktree"):
        targets_for(_call("write_file", {"path": "a\x00b", "content": "x"}))


def test_targets_wrapper_forms_map_to_their_first_token():
    assert targets_for(_call("bash", {"command": "FOO=1 rm x"})) == ("cmd:FOO=1",)
    assert targets_for(_call("bash", {"command": "env rm x"})) == ("cmd:env",)


@pytest.mark.parametrize(
    "command",
    [
        "cat /etc/passwd",
        "cat ~/.ssh/id",
        "ls ../..",
        "cat a/../../b",
        "pytest --out=/etc/x",
        "pytest --rootdir=../..",
    ],
)
def test_targets_reject_shell_path_escape(command):
    with pytest.raises(ScopeError, match="scope: shell path escapes worktree"):
        targets_for(_call("bash", {"command": command}))


def test_targets_shell_relative_paths_ok():
    assert targets_for(_call("bash", {"command": "pytest -q payments"})) == (
        "cmd:pytest",
    )


@pytest.mark.parametrize("path", [".mandate/swarm.json", ".muse/hooks.json"])
def test_targets_reject_protected_paths(path):
    with pytest.raises(ScopeError, match="scope: protected path"):
        targets_for(_call("edit_file", {"path": path}))


@pytest.mark.parametrize("path", ["../../x", "/etc/passwd", "a\x00b"])
def test_targets_reject_pass_tool_path_escape(path):
    with pytest.raises(ScopeError, match="scope: path escapes worktree"):
        targets_for(_call("read_file", {"path": path}))


def test_targets_pass_tool_relative_path_has_no_atoms():
    assert targets_for(_call("read_file", {"path": "deploy/prod.env.example"})) == ()


@pytest.mark.parametrize("workdir", ["/", "/etc", "..", "a/../..", WT + "/../x"])
def test_targets_reject_shell_workdir_escape(workdir):
    call = _call("bash", {"command": "cat passwd", "workdir": workdir})
    with pytest.raises(ScopeError, match="scope: shell path escapes worktree"):
        targets_for(call)


@pytest.mark.parametrize("workdir", ["", "payments", WT, WT + "/payments"])
def test_targets_shell_workdir_inside_cwd_ok(workdir):
    call = _call("bash", {"command": "ls", "workdir": workdir})
    assert targets_for(call) == ("cmd:ls",)


MANDATE_TOOLS = (
    "mcp__mandate__quote_payment",
    "mcp__mandate__get_payment_status",
    "mcp__mandate__confirm_payment",
    "mcp__mandate__get_receipt",
    "mcp__mandate__get_intent",
)


@pytest.mark.parametrize("tool", MANDATE_TOOLS)
def test_classify_mandate_mcp_tools(tool):
    assert classify(tool) is Kind.PASS
    assert targets_for(_call(tool, {"quote_id": "q:000001"})) == ()


@pytest.mark.parametrize(
    "tool",
    ["mcp__other__pay", "mcp__mandate__transfer", "mcp__mandate_x__get_receipt"],
)
def test_classify_other_mcp_tools_denied(tool):
    assert classify(tool) is Kind.DENY


@pytest.mark.parametrize(
    "command",
    [
        "git rm .muse/hooks.json",
        "cat ./.mandate/state.json",
        "cat .MUSE/hooks.json",
        "git -C.muse status",
        "pytest --rootdir=.mandate",
    ],
)
def test_targets_reject_shell_protected_paths(command):
    with pytest.raises(ScopeError, match="scope: protected path"):
        targets_for(_call("bash", {"command": command}))


@pytest.mark.parametrize(
    "command",
    [
        "pytest -c/etc/evil.ini",
        "gcc -I~/include x.c",
        "ls x:/etc",
        "scp host:../secret out",
    ],
)
def test_targets_reject_glued_shell_paths(command):
    with pytest.raises(ScopeError, match="scope: shell path escapes worktree"):
        targets_for(_call("bash", {"command": command}))


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("read_file", {"file_path": "/etc/passwd"}),
        ("read_file", {"file_path": 7}),
        ("grep", {"pattern": "x", "paths": ["src", "/etc"]}),
        ("grep", {"pattern": "x", "paths": "src"}),
        ("grep", {"pattern": "x", "dir": "../.."}),
        ("glob", {"pattern": "/Users/**"}),
        ("search", {"cwd": "/"}),
    ],
)
def test_targets_reject_pass_tool_path_keys(tool, tool_input):
    with pytest.raises(ScopeError, match="scope: path escapes worktree"):
        targets_for(_call(tool, tool_input))


def test_targets_grep_pattern_is_not_a_path():
    assert targets_for(_call("grep", {"pattern": "^/usr", "path": "src"})) == ()


@pytest.mark.parametrize("command", ["cat x=y=/etc", "cat a:b:/etc/x", "cat -a=b=/etc"])
def test_targets_reject_multi_separator_escapes(command):
    with pytest.raises(ScopeError, match="scope: shell path escapes worktree"):
        targets_for(_call("bash", {"command": command}))


def test_targets_reject_multi_separator_protected():
    with pytest.raises(ScopeError, match="scope: protected path"):
        targets_for(_call("bash", {"command": "cat x:y:.muse/z"}))


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("read_file", {"filePath": "/etc/passwd"}),
        ("read_file", {"path": "~/.ssh/id"}),
        ("read_file", {"path": "~"}),
        ("grep", {"pattern": "x", "include": "/etc"}),
        ("grep", {"pattern": "x", "opts": {"deep": ["a", "../b"]}}),
        ("glob", {"pattern": "{/etc,x}"}),
        ("glob", {"pattern": "src/{a,b}"}),
    ],
)
def test_targets_reject_unknown_pass_tool_strings(tool, tool_input):
    with pytest.raises(ScopeError, match="scope: path escapes worktree"):
        targets_for(_call(tool, tool_input))


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("search", {"query": "/etc/passwd"}),
        ("search", {"pattern": "^/usr", "limit": 5, "flag": True, "x": None}),
        ("grep", {"pattern": "^/usr", "path": "src", "context": 2}),
        ("mcp__mandate__get_receipt", {"quote_id": "q:000001"}),
    ],
)
def test_targets_pass_tool_text_and_non_strings_allowed(tool, tool_input):
    assert targets_for(_call(tool, tool_input)) == ()
