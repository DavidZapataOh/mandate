"""Differential check: real shells run exactly what the hook reader allowed.

Recorder executables stand in for every program on PATH and log the argv they
were started with. For every command the reader accepts within the allowed
atoms, the programs the shell runs must be exactly the reader's atoms, every
argv must be one the reader parsed, every argument must stay inside the
worktree and outside its protected directories, and an allowed governed
command must run its argv once. Each command runs twice, with recorders that
succeed and with recorders that fail, so both sides of `&&` and `||` run at
least once. Commands the reader refuses never reach a shell here; their
reasons are pinned by the reader's own tests.
"""

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from swarm.hookio import _SEGMENTS, ScopeError, targets_for
from swarm.test_hookio import _call

GOVERNED = frozenset({"nimbus"})
ALLOWED = frozenset(
    {
        "cmd:nimbus deploy api-v2 prod-eu",
        "cmd:nimbus status prod-eu",
        "cmd:cat",
        "cmd:ls",
    }
)


def _shell(label, path, kind, same_as=None):
    found = shutil.which(path)
    duplicate = bool(found and same_as and found == shutil.which(same_as))
    duplicate = duplicate or bool(
        found
        and same_as
        and shutil.which(same_as)
        and os.path.realpath(found) == os.path.realpath(shutil.which(same_as))
    )
    return pytest.param(
        (found, kind),
        id=label,
        marks=pytest.mark.skipif(
            not found or duplicate, reason=f"{label}: absent or same as {same_as}"
        ),
    )


# bash on PATH is often a newer build than /bin/bash (macOS ships 3.2, where
# `.*` still matches `..`), so both run.
SHELLS = [
    _shell("bash", "bash", "bash"),
    _shell("/bin/bash", "/bin/bash", "bash", same_as="bash"),
    _shell("zsh", "zsh", "zsh"),
    _shell("sh", "sh", "sh"),
]
FLAGS = {"bash": ["--noprofile", "--norc"], "zsh": ["-f"], "sh": []}
# One append per record, so programs in a pipeline cannot interleave records.
RECORDER = "\n".join(
    [
        "#!/bin/sh",
        'rec=$(printf \'%s\\037\' "${0##*/}" "$@")',
        'printf \'%s\\n\' "$rec" >> "$EXEC_LOG"',
        'exit "${EXEC_STATUS:-0}"',
        "",
    ]
)
# Shells split words on space and tab only, so these run as program names.
ODD_BLANKS = ("\x0b", "\x0c", "\x1c", "\x85", "\xa0", " ", "　")
PROGRAMS = ("nimbus", "cat", "ls", *ODD_BLANKS)
DECOYS = ("api-v2", "api-vX", "prod-eu", "RUNBOOK.md")
PROTECTED = frozenset({".mandate", ".muse"})
STATUSES = ("0", "1")


@pytest.fixture(scope="module")
def sandbox(tmp_path_factory):
    base = tmp_path_factory.mktemp("shell")
    bin_dir = base / "bin"
    bin_dir.mkdir()
    for name in PROGRAMS:
        path = bin_dir / name
        path.write_text(RECORDER)
        path.chmod(0o755)
    work = base / "work"
    work.mkdir()
    for name in DECOYS:
        (work / name).write_text("")
    # The live layout: authority state beside the worktree, Mandate and Muse
    # Code configuration inside it.
    for rel in ("authority/state.json", "work/.mandate/gate.key", "work/.muse/x"):
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text("")
    # Empty startup-file directory: no rc file can alias or reconfigure.
    home = base / "home"
    home.mkdir()
    return base


def _run(shell, args, stdin, sandbox, status):
    log = sandbox / "exec.log"
    log.write_bytes(b"")
    home = sandbox / "home"
    path, kind = shell
    subprocess.run(  # noqa: S603
        [path, *FLAGS[kind], *args],
        input=stdin.encode(),
        cwd=sandbox / "work",
        env={
            "PATH": str(sandbox / "bin"),
            "EXEC_LOG": str(log),
            "EXEC_STATUS": status,
            "HOME": str(home),
            "ZDOTDIR": str(home),
        },
        capture_output=True,
        timeout=10,
        check=False,
        start_new_session=True,
    )
    text = log.read_bytes().decode("utf-8", "surrogateescape")
    # Split on newline only: str.splitlines also splits on the odd blanks.
    return [line.split("\x1f")[:-1] for line in text.split("\n")[:-1]]


def _executed(shell, command, sandbox, status="0"):
    return _run(shell, ["-c", command], "", sandbox, status)


def _session(shell, lines, sandbox, status):
    return _run(shell, ["-i"], "".join(f"{line}\n" for line in lines), sandbox, status)


def _atom(argv):
    if argv[0].casefold() in GOVERNED:
        return "cmd:" + " ".join(argv)
    return f"cmd:{argv[0]}"


def _allowed(command):
    try:
        atoms = targets_for(_call("bash", {"command": command}), GOVERNED)
    except ScopeError:
        return None
    return atoms if set(atoms) <= ALLOWED else None


def _governed(atoms):
    return [a for a in atoms if a.split(" ", 1)[0].casefold() == "cmd:nimbus"]


def _parsed(command):
    return [argv for seg in _SEGMENTS.split(command) if (argv := shlex.split(seg))]


def _contained(word, work):
    for part in (word, *word.replace(":", "=").split("=")):
        path = os.path.normpath(work / part)
        rel = os.path.relpath(path, work)
        if rel == ".." or rel.startswith("../"):
            return False
        if any(seg.casefold() in PROTECTED for seg in rel.split("/")):
            return False
    return True


def _assert_ran_exactly(atoms, argvs, runs, context, sandbox):
    work = sandbox / "work"
    ran = {status: [_atom(argv) for argv in argv_list] for status, argv_list in runs}
    for status, ran_atoms in ran.items():
        assert set(ran_atoms) <= set(atoms), (context, status, ran_atoms)
        assert _governed(ran_atoms) == _governed(atoms), (context, status, ran_atoms)
    assert set().union(*ran.values()) == set(atoms), (context, ran)
    for status, argv_list in runs:
        for argv in argv_list:
            assert argv in argvs, (context, status, argv, argvs)
            assert all(_contained(w, work) for w in argv[1:]), (context, argv)


def _check(shell, command, sandbox):
    atoms = _allowed(command)
    if atoms is None:
        return
    runs = [(s, _executed(shell, command, sandbox, s)) for s in STATUSES]
    _assert_ran_exactly(atoms, _parsed(command), runs, command, sandbox)


def _check_session(shell, lines, sandbox):
    read = [_allowed(line) for line in lines]
    if any(atoms is None for atoms in read):
        return
    atoms = [atom for line_atoms in read for atom in line_atoms]
    argvs = [argv for line in lines for argv in _parsed(line)]
    runs = [(s, _session(shell, lines, sandbox, s)) for s in STATUSES]
    _assert_ran_exactly(atoms, argvs, runs, lines, sandbox)


WORDS = [
    "nimbus",
    "deploy",
    "api-v2",
    "prod-eu",
    "status",
    "migrate",
    "cat",
    "ls",
    "RUNBOOK.md",
    "!!",
    "!!:2",
    "!-1",
    "!#",
    "^ls^nimbus",
    *ODD_BLANKS,
    "..",
    ".*",
    ".?",
    ".m*",
    ".mandate",
    ".MUSE/x",
    "../authority/state.json",
    "x=..",
    "--f=.muse",
    "./RUNBOOK.md",
]
TWISTS = [
    lambda w: w,
    lambda w: w,
    lambda w: w,
    lambda w: f"'{w}'",
    lambda w: f'"{w}"',
    lambda w: "\\" + w,
    lambda w: w[:-1] + "?",
    lambda w: w + "*",
    lambda w: w.upper(),
    lambda w: "=" + w,
    lambda w: w + "#",
    lambda w: w + "!",
    lambda w: "X=1 " + w,
    lambda w: w + "\x1b",
    lambda w: w + "\x7f",
    lambda w: "\x16" + w,
]
JOINS = [" ", " ", "\t", "  ", " ; ", " && ", " || ", " | ", " # ", "\\ ", ";"]


@st.composite
def commands(draw):
    words = draw(st.lists(st.sampled_from(WORDS), min_size=1, max_size=5))
    out = ""
    for index, word in enumerate(words):
        if index:
            out += draw(st.sampled_from(JOINS))
        out += draw(st.sampled_from(TWISTS))(word)
    return out


@st.composite
def near_deploy(draw):
    words = ["nimbus", "deploy", "api-v2", "prod-eu"]
    index = draw(st.integers(0, 3))
    words[index] = draw(st.sampled_from(TWISTS))(words[index])
    joins = [draw(st.sampled_from(JOINS[:4])) for _ in range(3)]
    return words[0] + "".join(j + w for j, w in zip(joins, words[1:], strict=True))


# Each of these passed the reader before globs were refused; on bash 3.2 and
# sh the first one hands `cat` the authority state beside the worktree.
GLOB_ESCAPES = [
    "cat .*/authority/state.json",
    "cat .?/authority/state.json",
    "ls .*",
    "cat .m*/gate.key",
    "cat .[m]use/x",
]
CORPUS = [
    *GLOB_ESCAPES,
    "cat =ls",
    "cat x=.. RUNBOOK.md",
    "cat --f=.muse",
    "cat ./RUNBOOK.md",
    "nimbus deploy api-v2 prod-eu",
    "  nimbus\tdeploy  api-v2 prod-eu ",
    "nimbus status prod-eu",
    "cat RUNBOOK.md && ls",
    "cat RUNBOOK.md || ls",
    "cat RUNBOOK.md | cat",
    "nimbus deploy api-v2 prod-eu && ls",
    "nimbus status prod-eu; cat RUNBOOK.md",
    '"nimbus deploy api-v2 prod-eu"',
    "nimbus\\ deploy api-v2 prod-eu",
    "'nimbus' deploy api-v2 prod-eu",
    "NIMBUS deploy api-v2 prod-eu",
    "nimbus deploy api-v? prod-eu",
    "cat RUNBOOK.md # ; nimbus migrate migration-0017 prod-eu",
    "cat !!:2 nimbus migrate migration-0017 prod-eu",
    "ls;\x0b",
    "ls;\xa0",
    "ls && 　",
    "cat RUNBOOK.md | \x1c",
    "ls;\x85",
    "ls;\x0c",
    "nimbus deploy\tapi-v2 prod-eu",
    "cat .mand\tgate.key",
    "ls .mu\t",
]
# Each session is one persistent interactive shell fed every line in turn.
SESSIONS = [
    ["nimbus status prod-eu", "nimbus deploy api-v2 prod-eu", "ls"],
    ["cat RUNBOOK.md | cat", "cat !!:2 nimbus migrate migration-0017 prod-eu"],
    [
        "cat RUNBOOK.md && ls",
        "cat !!:s/ls/nimbus migrate migration-0017 prod-eu/",
    ],
    ["ls", "^ls^nimbus migrate migration-0017 prod-eu"],
    ["nimbus deploy api-v2 prod-eu", "ls !-1:s/deploy/migrate/"],
    ["nimbus deploy api-v2 prod-eu", "cat RUNBOOK.md", "ls"],
    ["nimbus deploy api-v2 prod-eu", "nimbus deploy\tapi-v2 prod-eu"],
    ["ls", "ls \x1b.", "ls \x16\t", "ls \x7f"],
]
# Readline completes on tab in interactive bash and sh: each of these ran a
# different argv there than the words the reader would have read.
TAB_COMPLETIONS = ["nimbus deploy\tapi-v2 prod-eu", "cat .mand\tgate.key", "ls .mu\t"]


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("command", CORPUS)
def test_corpus_runs_only_what_the_hook_allowed(shell, command, sandbox):
    _check(shell, command, sandbox)


@pytest.mark.parametrize("command", TAB_COMPLETIONS)
def test_tab_completion_shapes_are_refused(command):
    assert _allowed(command) is None


@pytest.mark.parametrize("command", GLOB_ESCAPES)
def test_glob_escapes_are_refused(command):
    assert _allowed(command) is None


@pytest.mark.parametrize("shell", SHELLS)
def test_argument_check_sees_what_a_glob_reaches(shell, sandbox):
    # Without this the containment check could pass on a harness where no glob
    # ever reached outside the worktree.
    ran = _executed(shell, "cat .*/authority/state.json", sandbox)
    if ran != [["cat", "../authority/state.json"]]:
        pytest.skip(f"{shell[0]}: `.*` does not match `..` here")
    assert not _contained(ran[0][1], sandbox / "work")


def test_argument_check_refuses_escapes_and_protected_dirs(tmp_path):
    for word in ("../x", "/etc/passwd", ".MUSE/x", "--f=.mandate/k", "a:../b"):
        assert not _contained(word, tmp_path), word
    for word in ("RUNBOOK.md", "./api-v2", "--f=x", "deploy"):
        assert _contained(word, tmp_path), word


@pytest.mark.parametrize("shell", SHELLS)
def test_canonical_deploy_runs_exactly_its_argv(shell, sandbox):
    assert _executed(shell, "nimbus deploy api-v2 prod-eu", sandbox) == [
        ["nimbus", "deploy", "api-v2", "prod-eu"]
    ]


@pytest.mark.parametrize("shell", SHELLS)
def test_interactive_session_expands_history_across_lines(shell, sandbox):
    # Without this the session checks could pass on a shell that never
    # expanded history. dash (sh on Debian and Ubuntu) has no history expansion.
    if Path(shell[0]).resolve().name == "dash":
        pytest.skip("dash has no history expansion")
    lines = ["cat RUNBOOK.md | cat", "cat !!:2 ls"]
    assert ["ls"] in _session(shell, lines, sandbox, "0")


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("lines", SESSIONS)
def test_interactive_sessions_run_only_what_the_hook_allowed(shell, lines, sandbox):
    _check_session(shell, lines, sandbox)


@pytest.mark.parametrize("shell", SHELLS)
@settings(max_examples=400, deadline=None, derandomize=True)
@given(command=st.one_of(commands(), near_deploy()))
def test_generated_commands_run_only_what_the_hook_allowed(shell, command, sandbox):
    _check(shell, command, sandbox)


@pytest.mark.parametrize("shell", SHELLS)
@settings(max_examples=150, deadline=None, derandomize=True)
@given(lines=st.lists(st.one_of(commands(), near_deploy()), min_size=2, max_size=4))
def test_generated_sessions_run_only_what_the_hook_allowed(shell, lines, sandbox):
    _check_session(shell, lines, sandbox)
