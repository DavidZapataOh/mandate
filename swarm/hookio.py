"""Muse Code hook payloads, tool classification and scope targets."""

import json
import posixpath
import re
import shlex
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_MALFORMED = "malformed hook payload"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SEGMENTS = re.compile(r"&&|\|\||;|\|")
# `!` is history expansion in interactive bash, zsh and sh.
_SHELL_FORBIDDEN = frozenset("\n\r\x00<>`$(){}!")
_PLAIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
_PLAIN_ARG = re.compile(r"-{0,2}[A-Za-z0-9][A-Za-z0-9._:=+-]*")
_BLANKS = re.compile(r" +")
# Words that make the next word the command (bash, zsh, sh), so their atom
# would name syntax instead of the program the shell runs.
_SHELL_KEYWORDS = frozenset(
    {
        "builtin",
        "case",
        "command",
        "coproc",
        "do",
        "done",
        "elif",
        "else",
        "end",
        "esac",
        "exec",
        "fi",
        "for",
        "foreach",
        "function",
        "if",
        "in",
        "nocorrect",
        "noglob",
        "repeat",
        "select",
        "then",
        "time",
        "until",
        "while",
    }
)
# Builtins and programs that run other words, re-run history, or change how a
# later call in the same shell resolves or parses its words.
_RUNNERS = frozenset(
    {
        "alias",
        "autoload",
        "caffeinate",
        "cd",
        "declare",
        "doas",
        "emulate",
        "enable",
        "env",
        "eval",
        "export",
        "fc",
        "hash",
        "history",
        "nice",
        "nohup",
        "popd",
        "pushd",
        "r",
        "readonly",
        "script",
        "set",
        "setopt",
        "setsid",
        "shopt",
        "source",
        "stdbuf",
        "sudo",
        "timeout",
        "trap",
        "typeset",
        "unalias",
        "unset",
        "unsetopt",
        "xargs",
        "zmodload",
    }
)
_SHELL_FIELDS = frozenset({"command", "description", "workdir"})
# Shells split words on space and tab, and tab is refused on its own; any other
# blank or control character is read differently by the shell and the reader.
_OTHER_BLANK_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Zs"})
_NOT_PLAIN_NAME = "scope: command name not plain"
_NOT_PLAIN = "scope: governed command not plain"
_ALONE = "scope: governed command must stand alone"
_FILE_TOOLS = frozenset({"write_file", "edit_file", "delete_file"})
_SHELL_TOOLS = frozenset({"bash", "shell", "exec_command"})
_PROTECTED = frozenset({".mandate", ".muse"})
MANDATE_MCP_TOOLS = frozenset(
    {
        "mcp__mandate__quote_payment",
        "mcp__mandate__get_payment_status",
        "mcp__mandate__confirm_payment",
        "mcp__mandate__get_receipt",
        "mcp__mandate__get_intent",
    }
)
_PATH_KEYS = ("path", "file_path", "dir", "cwd")
_PASS_TOOLS = frozenset(
    {
        "read_file",
        "glob",
        "grep",
        "search",
        "subagent_wait",
        "subagent_read_result",
        "submit_reminder_decision",
    }
)


class ScopeError(ValueError):
    """A tool call cannot be mapped to exact scope atoms."""


class Kind(StrEnum):
    PASS = "pass"  # noqa: S105
    SPAWN = "spawn"
    GOVERNED = "governed"
    DENY = "deny"


@dataclass(frozen=True)
class SessionStarted:
    session_id: str
    cwd: str


@dataclass(frozen=True)
class ChildStarted:
    subagent_id: str
    child_session_id: str


@dataclass(frozen=True)
class ToolCall:
    session_id: str
    tool: str
    tool_input: dict[str, Any]
    cwd: str
    model: str
    tool_use_id: str


HookEvent = SessionStarted | ChildStarted | ToolCall


def _strings(payload: dict[str, Any], *keys: str) -> list[str]:
    values = [payload.get(key) for key in keys]
    if not all(isinstance(v, str) for v in values):
        raise ValueError(_MALFORMED)
    return values  # type: ignore[return-value]


def parse_event(payload: object) -> HookEvent:
    """Turn a hook stdin payload into a typed event.

    Raises:
        ValueError: The payload is not a recognised, complete hook event.
    """
    if not isinstance(payload, dict):
        raise ValueError(_MALFORMED)
    name = payload.get("hook_event_name")
    if name == "SessionStart":
        session_id, cwd = _strings(payload, "session_id", "cwd")
        return SessionStarted(session_id, cwd)
    if name == "SubagentStart":
        subagent_id, child_session_id = _strings(
            payload, "subagent_id", "child_session_id"
        )
        return ChildStarted(subagent_id, child_session_id)
    if name == "PreToolUse":
        session_id, tool, cwd, model, tool_use_id = _strings(
            payload, "session_id", "tool_name", "cwd", "model", "tool_use_id"
        )
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            raise ValueError(_MALFORMED)
        return ToolCall(session_id, tool, tool_input, cwd, model, tool_use_id)
    raise ValueError(_MALFORMED)


def is_observer(event: ChildStarted) -> bool:
    """Whether the child is a built-in observer agent rather than a real subagent."""
    return _UUID.fullmatch(event.subagent_id) is None


def deny_output(reason: str) -> str:
    """Render the PreToolUse deny decision Muse Code expects on stdout."""
    if not reason:
        raise ValueError("deny reason required")
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        },
        separators=(",", ":"),
    )


def classify(tool: str) -> Kind:
    """Classify a tool name; anything unknown is denied."""
    if tool in _PASS_TOOLS or tool in MANDATE_MCP_TOOLS:
        return Kind.PASS
    if tool == "subagent_spawn":
        return Kind.SPAWN
    if tool in _FILE_TOOLS or tool in _SHELL_TOOLS:
        return Kind.GOVERNED
    return Kind.DENY


def _relative(path: str) -> str:
    if "\x00" in path or posixpath.isabs(path) or path.startswith("~"):
        raise ScopeError("scope: path escapes worktree")
    rel = posixpath.normpath(path)
    if rel == ".." or rel.startswith("../"):
        raise ScopeError("scope: path escapes worktree")
    return rel


def _file_atom(tool_input: dict[str, Any]) -> str:
    path = tool_input.get("path")
    if not isinstance(path, str) or not path:
        raise ScopeError("scope: missing tool target")
    rel = _relative(path)
    if rel.split("/", 1)[0].casefold() in _PROTECTED:
        raise ScopeError("scope: protected path")
    return f"file:{rel}"


def _candidates(token: str) -> list[str]:
    fragments = re.split(r"[=:]", token)
    found = [token, *fragments]
    for part in (token, *fragments):
        if part.startswith("-") and not part.startswith("--") and len(part) > 2:
            found.append(part[2:])
    return found


def _escapes(candidate: str) -> bool:
    return candidate.startswith(("/", "~")) or ".." in candidate.split("/")


def _protected(candidate: str) -> bool:
    return any(seg.casefold() in _PROTECTED for seg in candidate.split("/"))


def _check_workdir(workdir: object, cwd: str) -> None:
    if workdir is None or workdir == "":
        return
    if not isinstance(workdir, str) or "\x00" in workdir:
        raise ScopeError("scope: shell path escapes worktree")
    path = posixpath.normpath(workdir)
    if posixpath.isabs(path):
        base = posixpath.normpath(cwd)
        if path != base and not path.startswith(base.rstrip("/") + "/"):
            raise ScopeError("scope: shell path escapes worktree")
    elif path == ".." or path.startswith("../"):
        raise ScopeError("scope: shell path escapes worktree")


def argv_atom(argv: Sequence[str]) -> str:
    """The scope atom of an argv-governed command: `cmd:` and its plain words."""
    return "cmd:" + " ".join(argv)


def _plain_name(name: str) -> bool:
    folded = name.casefold()
    return (
        _PLAIN_NAME.fullmatch(name) is not None
        and folded not in _SHELL_KEYWORDS
        and folded not in _RUNNERS
    )


def _other_blank(char: str) -> bool:
    if char == " ":
        return False
    return char.isspace() or unicodedata.category(char) in _OTHER_BLANK_CATEGORIES


def plain_argv(argv: Sequence[str]) -> bool:
    """Whether every word is plain: the shell passes it on unchanged."""
    return (
        bool(argv)
        and _plain_name(argv[0])
        and all(_PLAIN_ARG.fullmatch(word) is not None for word in argv[1:])
    )


def _governed_atom(segment: str, argv: list[str], alone: bool) -> str:
    if not alone:
        raise ScopeError(_ALONE)
    if _BLANKS.split(segment.strip(" ")) != argv or not plain_argv(argv):
        raise ScopeError(_NOT_PLAIN)
    return argv_atom(argv)


def _shell_atoms(
    tool_input: dict[str, Any], cwd: str, governed: frozenset[str]
) -> tuple[str, ...]:
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip(" "):
        raise ScopeError("scope: missing tool target")
    if _SHELL_FORBIDDEN.intersection(command) or "&" in command.replace("&&", ""):
        raise ScopeError("scope: shell redirection or substitution")
    _check_workdir(tool_input.get("workdir"), cwd)
    # Interactive bash and sh read even piped input through readline, where a
    # tab completes the word before it into a name the reader never saw.
    if "\t" in command:
        raise ScopeError("scope: unparseable shell command")
    commands: list[tuple[str, list[str]]] = []
    candidates: list[str] = []
    for segment in _SEGMENTS.split(command):
        try:
            argv = shlex.split(segment)
        except ValueError:
            raise ScopeError("scope: unparseable shell command") from None
        candidates.extend(c for token in argv for c in _candidates(token))
        if argv:
            commands.append((segment, argv))
    if any(_escapes(c) for c in candidates):
        raise ScopeError("scope: shell path escapes worktree")
    if any(_protected(c) for c in candidates):
        raise ScopeError("scope: protected path")
    if not _SHELL_FIELDS.issuperset(tool_input):
        raise ScopeError("scope: unknown shell tool field")
    names = frozenset(name.casefold() for name in governed)
    alone = _SEGMENTS.search(command) is None
    atoms: dict[str, None] = {}
    for segment, argv in commands:
        name = argv[0]
        if not _plain_name(name):
            raise ScopeError(_NOT_PLAIN_NAME)
        if name.casefold() in names:
            atoms[_governed_atom(segment, argv, alone)] = None
        else:
            atoms[f"cmd:{name}"] = None
    if any(_other_blank(char) for char in command):
        raise ScopeError("scope: unparseable shell command")
    if not atoms:
        raise ScopeError("scope: missing tool target")
    return tuple(atoms)


_TEXT_KEYS = {"grep": frozenset({"pattern"}), "search": frozenset({"query", "pattern"})}


def _check_strings(value: object) -> None:
    if isinstance(value, str):
        _relative(value)
    elif isinstance(value, dict):
        for item in value.values():
            _check_strings(item)
    elif isinstance(value, list):
        for item in value:
            _check_strings(item)


def _check_pass_paths(call: ToolCall) -> None:
    for key in _PATH_KEYS:
        if key in call.tool_input and not isinstance(call.tool_input[key], str):
            raise ScopeError("scope: path escapes worktree")
    if "paths" in call.tool_input:
        paths = call.tool_input["paths"]
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            raise ScopeError("scope: path escapes worktree")
    if call.tool == "glob":
        pattern = call.tool_input.get("pattern")
        if isinstance(pattern, str) and ("{" in pattern or "}" in pattern):
            raise ScopeError("scope: path escapes worktree")
    skip = _TEXT_KEYS.get(call.tool, frozenset())
    for key, value in call.tool_input.items():
        if key not in skip:
            _check_strings(value)


def targets_for(
    call: ToolCall, governed: frozenset[str] = frozenset()
) -> tuple[str, ...]:
    """Map a tool call to exact scope atoms, failing closed.

    Args:
        call: The tool call to map.
        governed: Binaries whose atoms name the whole argv.

    Raises:
        ScopeError: The call escapes the worktree, touches Mandate or Muse Code
            configuration, hides a write, or cannot be expressed as exact atoms.
    """
    if call.tool in _FILE_TOOLS:
        return (_file_atom(call.tool_input),)
    if call.tool in _SHELL_TOOLS:
        return _shell_atoms(call.tool_input, call.cwd, governed)
    if call.tool == "apply_patch":
        raise ScopeError("scope: apply_patch not governed; use edit_file")
    kind = classify(call.tool)
    if kind is Kind.DENY:
        raise ScopeError(f"unclassified tool: {call.tool}")
    if kind is Kind.PASS:
        _check_pass_paths(call)
    return ()
