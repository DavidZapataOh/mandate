import re

import pytest

from swarm.hookio import ScopeError, targets_for
from swarm.test_hookio import _call

GOVERNED = frozenset({"nimbus"})
DEPLOY = "cmd:nimbus deploy api-v2 prod-eu"


def _atoms(command):
    return targets_for(_call("bash", {"command": command}), GOVERNED)


@pytest.mark.parametrize(
    ("command", "atoms"),
    [
        ("nimbus deploy api-v2 prod-eu", (DEPLOY,)),
        ("  nimbus deploy  api-v2 prod-eu ", (DEPLOY,)),
        ("nimbus status prod-eu", ("cmd:nimbus status prod-eu",)),
        (
            "nimbus migrate migration-0017 prod-eu",
            ("cmd:nimbus migrate migration-0017 prod-eu",),
        ),
        ("nimbus deploy api-v2 prod-eu --dry-run", (DEPLOY + " --dry-run",)),
        ("NIMBUS deploy api-v2 prod-eu", ("cmd:NIMBUS deploy api-v2 prod-eu",)),
        ("nimbus", ("cmd:nimbus",)),
        ("cat RUNBOOK.md && ls", ("cmd:cat", "cmd:ls")),
        ("sh -c 'nimbus migrate migration-0017 prod-eu'", ("cmd:sh",)),
    ],
)
def test_argv_atoms_name_the_whole_command(command, atoms):
    assert _atoms(command) == atoms


NOT_PLAIN_NAME = "scope: command name not plain"
NOT_PLAIN = "scope: governed command not plain"
ALONE = "scope: governed command must stand alone"
SUBST = "scope: shell redirection or substitution"
ESCAPE = "scope: shell path escapes worktree"
UNPARSEABLE = "scope: unparseable shell command"


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ('"nimbus deploy api-v2 prod-eu"', NOT_PLAIN_NAME),
        ("nimbus\\ deploy api-v2 prod-eu", NOT_PLAIN_NAME),
        ("PATH=. nimbus deploy api-v2 prod-eu", NOT_PLAIN_NAME),
        ("NIMBUS_ENV=prod-us nimbus deploy api-v2 prod-eu", NOT_PLAIN_NAME),
        ("./nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("bin/nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("=nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("-nimbus deploy api-v2 prod-eu", NOT_PLAIN_NAME),
        ("'nimbus' deploy api-v2 prod-eu", NOT_PLAIN),
        ('nim"bus" deploy api-v2 prod-eu', NOT_PLAIN),
        ("nimbus deploy 'api-v2' prod-eu", NOT_PLAIN),
        ("nimbus deploy api-v\\2 prod-eu", NOT_PLAIN),
        ("nimbus deploy api-v? prod-eu", NOT_PLAIN),
        ("nimbus deploy api-v* prod-eu", NOT_PLAIN),
        ("nimbus deploy api-v[2] prod-eu", NOT_PLAIN),
        ("nimbus deploy api-v2 prod-eu # migrate", NOT_PLAIN),
        ("nimbus deploy api-v2 prod-eu!", SUBST),
        ("nimbus @args.txt", NOT_PLAIN),
        ("nimbus deploy api-v2 prod-eu\x0bmigrate", NOT_PLAIN),
        ("nimbus deploy api‑v2 prod-eu", NOT_PLAIN),
        ("nimbus deploy api-v2 prod-eu;", ALONE),
        ("nimbus deploy api-v2 prod-eu && ls", ALONE),
        ("yes | nimbus deploy api-v2 prod-eu", ALONE),
        ("ls; nimbus migrate migration-0017 prod-eu", ALONE),
        ("nimbus deploy api-v2 prod-eu || nimbus migrate migration-0017", ALONE),
        ("nimbus deploy api-v2 prod-eu & nimbus migrate", SUBST),
        ("nimbus deploy api-v2 prod-eu > out", SUBST),
        ("nimbus deploy $(echo api-v2) prod-eu", SUBST),
        ("nimbus deploy api-v2 prod-eu\nnimbus migrate", SUBST),
        ("/usr/local/bin/nimbus deploy api-v2 prod-eu", ESCAPE),
        ("nimbus deploy ~ prod-eu", ESCAPE),
        ("nimbus deploy --config=../x", ESCAPE),
        ("nimbus deploy api-v2 'prod-eu", UNPARSEABLE),
    ],
)
def test_shell_tricks_never_yield_an_argv_atom(command, reason):
    with pytest.raises(ScopeError, match=reason):
        _atoms(command)


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ("time nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("TIME nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("coproc nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("noglob nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("nocorrect nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("repeat 2 nimbus deploy api-v2 prod-eu", NOT_PLAIN_NAME),
        ("if [[ -n x ]] nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("exec nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("command nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("builtin nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("! nimbus migrate migration-0017 prod-eu", SUBST),
        ("- nimbus migrate migration-0017 prod-eu", NOT_PLAIN_NAME),
        ("nіmbus deploy api-v2 prod-eu", NOT_PLAIN_NAME),
        ("ｎｉｍｂｕｓ deploy api-v2 prod-eu", NOT_PLAIN_NAME),
        ("nimbus deploy api-v2 prod-eu", NOT_PLAIN_NAME),
        ("\x0bnimbus deploy api-v2 prod-eu", NOT_PLAIN_NAME),
        ("nimbus deploy api-v2 prod-eu", NOT_PLAIN),
        ("nimbus deploy api-v2 prod-eu", NOT_PLAIN),
        ("nimbus deploy api-v2 prod-eu\x0cmigrate", NOT_PLAIN),
        ("nimbus deploy api-v2 ''", NOT_PLAIN),
        ('nimbus deploy api-v2 ""', NOT_PLAIN),
        ("nimbus deploy =ls prod-eu", NOT_PLAIN),
        ("nimbus deploy ^api-v1 prod-eu", NOT_PLAIN),
        ("nimbus deploy %1 prod-eu", NOT_PLAIN),
        ("nimbus deploy api-v2 prod-eu,prod-us", NOT_PLAIN),
        ("nimbus --=x deploy", NOT_PLAIN),
        ("nimbus ---deploy api-v2", NOT_PLAIN),
        ("nimbus deploy api-v2 prod-eu;;", ALONE),
        ("nimbus deploy api-v2 prod-eu\r", SUBST),
        ("nimbus deploy api-v2 prod-eu\x00", SUBST),
        ("nimbus deploy api-v2 \\\nprod-eu", SUBST),
        ("nimbus deploy api-v2 prod-eu <<EOF", SUBST),
        ("nimbus deploy {api-v2,api-v1} prod-eu", SUBST),
        ("nimbus deploy api-v2 prod-eu |& cat", SUBST),
        ("nimbus deploy api-v2 prod-eu\\", UNPARSEABLE),
    ],
)
def test_shell_keywords_and_lookalikes_never_yield_an_argv_atom(command, reason):
    with pytest.raises(ScopeError, match=re.escape(reason)):
        _atoms(command)


# Interactive bash and sh read input through readline even from a pipe: a tab
# completes the word before it, and other control keys edit the line.
@pytest.mark.parametrize(
    "command",
    [
        "nimbus deploy\tapi-v2 prod-eu",
        "cat .mand\tgate.key",
        "ls .mu\t",
        "nimbus deploy api-v2 prod-eu\t",
        "  nimbus\tdeploy  api-v2 prod-eu ",
        "\tls",
        "cat RUNBOOK.md\t&& ls",
        "ls \x1b.",
        "ls \x1b[A",
        "ls \x7f",
        "ls \x16\t",
        "ls \x16",
        "ls \x01",
        "ls \x05",
        "ls \x08",
        "ls \x12",
        "ls \x15",
        "ls \x17",
        "ls \x18\x05",
        "ls \x19",
        "ls \x1f",
    ],
)
def test_readline_keys_are_refused_anywhere(command):
    with pytest.raises(ScopeError, match=re.escape(UNPARSEABLE)):
        _atoms(command)


@pytest.mark.parametrize("key", ["\x7f", "\x1b", "\x16"])
def test_readline_keys_in_a_governed_command_are_refused(key):
    with pytest.raises(ScopeError, match=re.escape(NOT_PLAIN)):
        _atoms("nimbus deploy api-v2 prod-eu" + key)


@pytest.mark.parametrize(
    "command",
    [
        "cat !!:2 nimbus migrate migration-0017 prod-eu",
        "ls !-1:s/a/b/",
        "cat !!:s/ls/nimbus migrate migration-0017 prod-eu/",
        "cat !$",
        "ls !#",
    ],
)
def test_history_expansion_is_refused_anywhere(command):
    with pytest.raises(ScopeError, match=re.escape(SUBST)):
        _atoms(command)


@pytest.mark.parametrize(
    "command",
    [
        "^ls^nimbus migrate migration-0017 prod-eu",
        "env nimbus migrate migration-0017 prod-eu",
        "env rm x",
        "alias nimbus=true",
        "unalias cat",
        "eval ls",
        "trap ls EXIT",
        "source RUNBOOK.md",
        ". RUNBOOK.md",
        "fc -s",
        "r",
        "history",
        "hash -p bin/nimbus nimbus",
        "enable -n cat",
        "autoload nimbus",
        "zmodload zsh/system",
        "xargs nimbus migrate",
        "nohup ls",
        "sudo ls",
        "doas ls",
        "nice ls",
        "timeout 5 ls",
        "caffeinate ls",
        "script out ls",
        "stdbuf -o0 ls",
        "setsid ls",
        "export PATH=bin",
        "set -k",
        "setopt MAGIC_EQUAL_SUBST",
        "unsetopt BANG_HIST",
        "unset PATH",
        "emulate sh",
        "shopt -s expand_aliases",
        "typeset -f",
        "declare -x PATH=bin",
        "readonly PATH",
        "cd",
        "pushd sub",
        "popd",
        "EVAL ls",
        "ls && Env rm x",
    ],
)
def test_runners_and_shell_state_builtins_are_not_command_names(command):
    with pytest.raises(ScopeError, match=re.escape(NOT_PLAIN_NAME)):
        _atoms(command)


@pytest.mark.parametrize(
    "command",
    [
        "ls;\x0b",
        "ls;\xa0",
        "ls && \u3000",
        "cat RUNBOOK.md | \x1c",
        "ls;\x85",
        "ls;\x0c",
        "x;\u2028",
        "ls;\u2029",
        "ls;\x1d",
        "ls;\x1e",
        "ls;\x1f",
        "\x0b",
    ],
)
def test_segment_of_other_whitespace_is_a_command_not_a_blank(command):
    with pytest.raises(ScopeError, match=re.escape(NOT_PLAIN_NAME)):
        _atoms(command)


@pytest.mark.parametrize(
    "command",
    [
        "ls \x0b",
        "cat RUNBOOK.md\xa0",
        "cat RUNBOOK.md \x1c",
        "cat a\x85b",
        "cat a\u3000b",
        "cat a\u2028b",
        "cat a\u200bb",
        "cat RUNBOOK\u202e.md",
        "cat a\x7fb",
        "cat a\x1bb",
        "cat a\ufeffb",
    ],
)
def test_other_whitespace_or_control_anywhere_is_refused(command):
    with pytest.raises(ScopeError, match=re.escape(UNPARSEABLE)):
        _atoms(command)


@pytest.mark.parametrize(
    "extra",
    [
        {"env": {"PATH": "bin"}},
        {"shell": "/bin/zsh"},
        {"login": True},
        {"cmd": "nimbus migrate migration-0017 prod-eu"},
        {"timeout": 5},
    ],
)
def test_unknown_shell_tool_fields_are_refused(extra):
    call = _call("bash", {"command": "ls", **extra})
    with pytest.raises(ScopeError, match=re.escape("scope: unknown shell tool field")):
        targets_for(call, GOVERNED)


def test_pinned_shell_tool_fields_are_read():
    tool_input = {"command": "ls", "description": "list", "workdir": ""}
    assert targets_for(_call("bash", tool_input), GOVERNED) == ("cmd:ls",)
