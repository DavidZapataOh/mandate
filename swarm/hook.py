"""Hook process Muse Code invokes to gate subagent tool calls.

Cmd atoms name the first binary of each shell segment, or the whole argv of a
binary the manifest governs by argv; a shell `workdir` must stay inside the
agent's cwd; code run by an allowed binary is contained by Muse Code's own OS
sandbox, not by Mandate.

Authority (manifest, state, keys, journal) lives in a state directory outside
the governed repo and is pinned by the hook's argv; nothing under the repo is
read as authority.
"""

import argparse
import fcntl
import json
import os
import posixpath
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from bank.credentials import credential_exposed
from gate.broker import action_within_scope, verify_chain
from gate.cava import CavaAction, Freshness, action_hash
from gate.certs import BitstringRevocation
from gate.events import DecisionEvent
from gate.policy import Verdict
from gate.shim import Mode
from swarm.attribution import Attribution, event_v2_json, from_hook
from swarm.hookio import (
    ChildStarted,
    HookEvent,
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
from swarm.state import (
    SwarmManifest,
    SwarmState,
    bind_lead,
    load_state,
    request_spawn,
    save_state,
    start_child,
)

_POLICY = "swarm"
_WORKTREES = ".muse/worktrees"
_OUTSIDE = "scope: cwd outside governed repo"


def _place(cwd: str, root: Path) -> str | None:
    """Where a pure, normalized `cwd` sits: "root", "worktree" or None."""
    if not posixpath.isabs(cwd) or "\x00" in cwd:
        return None
    path = posixpath.normpath(cwd)
    base = posixpath.normpath(str(root))
    if path == base:
        return "root"
    if path.startswith(posixpath.join(base, _WORKTREES) + "/"):
        return "worktree"
    return None


@dataclass
class _Ctx:
    state_dir: Path
    root: Path
    manifest: SwarmManifest
    state: SwarmState
    now: int
    nonce: str
    started: float

    def save(self, state: SwarmState) -> None:
        self.state = state
        save_state(state, self.state_dir / "state.json")

    def journal(
        self,
        agent: str,
        tool: str,
        targets: tuple[str, ...],
        verdict: Verdict,
        why: str,
        tool_use_id: str | None = None,
        meta: Attribution | None = None,
    ) -> None:
        action = CavaAction(
            version="cava/1",
            runtime="muse-code",
            executable=tool,
            operation="invoke",
            category="code",
            targets=tuple(sorted(targets)),
            reversible=False,
            freshness=Freshness(self.nonce, self.now),
            evidence_refs=(),
        )
        event = DecisionEvent(
            v=1,
            event_id=f"evt:{self.nonce}",
            ts=self.now,
            mode=Mode.ENFORCE,
            verdict=verdict,
            action_hash=action_hash(action),
            policy_id=_POLICY,
            cert_jti=None,
            reason=why,
            latency_us=(time.perf_counter() - self.started) * 1e6,
        )
        record: dict[str, object] = {
            "agent": agent,
            "tool": tool,
            "targets": sorted(targets),
        }
        if tool_use_id is not None:
            record["tool_use_id"] = tool_use_id
        record["event"] = json.loads(event_v2_json(event, meta))
        line = json.dumps(record, separators=(",", ":"))
        with (self.state_dir / "journal.jsonl").open("a") as handle:
            handle.write(line + "\n")

    def deny(
        self,
        call: ToolCall,
        targets: tuple[str, ...],
        why: str,
        verdict: Verdict = Verdict.NOT_MET,
    ) -> tuple[int, str]:
        try:
            self.journal(
                call.session_id,
                call.tool,
                targets,
                verdict,
                why,
                call.tool_use_id,
                from_hook(call),
            )
        except Exception:  # noqa: S110
            pass  # a deny must survive a journal failure
        return 0, deny_output(why)

    def allow(
        self, call: ToolCall, targets: tuple[str, ...], why: str
    ) -> tuple[int, str]:
        self.journal(
            call.session_id,
            call.tool,
            targets,
            Verdict.MET,
            why,
            call.tool_use_id,
            from_hook(call),
        )
        return 0, ""


def _spawn(ctx: _Ctx, call: ToolCall) -> tuple[int, str]:
    role = call.tool_input.get("role")
    if not isinstance(role, str):
        return ctx.deny(call, (), "spawn: role required")
    isolated = call.tool_input.get("worktree_isolation") is True
    state, ok, why = request_spawn(
        ctx.state, ctx.manifest, call.session_id, role, isolated, ctx.now
    )
    if state is not ctx.state:
        ctx.save(state)
    targets = (f"role:{role}",)
    return ctx.allow(call, targets, why) if ok else ctx.deny(call, targets, why)


def _governed(ctx: _Ctx, call: ToolCall) -> tuple[int, str]:
    try:
        atoms = targets_for(call, ctx.manifest.argv_governed)
    except ScopeError as err:
        return ctx.deny(call, (), str(err))
    record = ctx.state.agents.get(call.session_id)
    if record is None:
        return ctx.deny(call, atoms, "scope: agent has no delegation")
    ok, why = verify_chain(
        record.chain,
        ctx.state.root_pub,
        ctx.manifest.root,
        ctx.now,
        BitstringRevocation(),
    )
    if not ok:
        return ctx.deny(call, atoms, why)
    action = CavaAction(
        version="cava/1",
        runtime="muse-code",
        executable=call.tool,
        operation="invoke",
        category="code",
        targets=tuple(sorted(atoms)),
        reversible=False,
        freshness=Freshness(ctx.nonce, ctx.now),
        evidence_refs=(),
    )
    ok, why = action_within_scope(record.chain[-1].scope, action)
    return ctx.allow(call, atoms, why) if ok else ctx.deny(call, atoms, why)


def _tool_call(ctx: _Ctx, call: ToolCall) -> tuple[int, str]:
    place = _place(call.cwd, ctx.root)
    if place is None:
        return ctx.deny(call, (), _OUTSIDE)
    kind = classify(call.tool)
    if kind is Kind.PASS:
        try:
            targets_for(call)
        except ScopeError as err:
            return ctx.deny(call, (), str(err))
        return 0, ""
    if kind is not Kind.DENY and call.session_id != ctx.state.lead:
        if place != "worktree":
            return ctx.deny(call, (), "scope: child outside its worktree")
    if kind is Kind.DENY:
        try:
            targets_for(call)
            why = f"unclassified tool: {call.tool}"
        except ScopeError as err:
            why = str(err)
        return ctx.deny(call, (), why, Verdict.NOT_CHECKABLE)
    if kind is Kind.SPAWN:
        return _spawn(ctx, call)
    return _governed(ctx, call)


def _fail(stdout_reason: str, pre_tool: bool) -> tuple[int, str]:
    return (0, deny_output(stdout_reason)) if pre_tool else (0, "")


def main(
    stdin: str,
    now: int,
    nonce: str,
    state_dir: Path,
    root: Path,
    exposed: bool = False,
) -> tuple[int, str]:
    """Decide one hook invocation; returns (exit code, stdout).

    Args:
        stdin: The raw hook payload.
        now: Current Unix time.
        nonce: Per-invocation nonce for the journal event.
        state_dir: Directory holding `swarm.json`, `state.json`, the journal and
            the lock; it must live outside the governed repo.
        root: The governed repo root; event cwds must be it or a worktree under
            `.muse/worktrees/`.
        exposed: Whether the hook's environment holds the bank key; the agent
            that spawned the hook then holds it too, so every call is refused.
    """
    started = time.perf_counter()
    if not stdin.strip():
        return 0, ""
    try:
        payload = json.loads(stdin)
    except Exception:
        return _fail("malformed: hook payload", True)
    pre_tool = (
        isinstance(payload, dict) and payload.get("hook_event_name") == "PreToolUse"
    )
    if exposed:
        return _fail("denied: bank credential in agent environment", pre_tool)
    try:
        return _decide(payload, pre_tool, now, nonce, started, state_dir, root)
    except Exception:
        return _fail("malformed: mandate error", pre_tool)


def _decide(
    payload: object,
    pre_tool: bool,
    now: int,
    nonce: str,
    started: float,
    state_dir: Path,
    root: Path,
) -> tuple[int, str]:
    try:
        event = parse_event(payload)
    except ValueError:
        return _fail("malformed: hook payload", pre_tool)
    assert isinstance(payload, dict)  # noqa: S101
    if not (state_dir / "state.json").is_file():
        return _fail("malformed: no mandate state", pre_tool)
    cwd = payload["cwd"] if isinstance(payload.get("cwd"), str) else ""
    with (state_dir / "state.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ctx = _Ctx(
            state_dir=state_dir,
            root=root,
            manifest=SwarmManifest.load(state_dir / "swarm.json"),
            state=load_state(state_dir / "state.json"),
            now=now,
            nonce=nonce,
            started=started,
        )
        return _locked(ctx, event, cwd)


def _locked(ctx: _Ctx, event: HookEvent, cwd: str) -> tuple[int, str]:
    if isinstance(event, ToolCall):
        return _tool_call(ctx, event)
    if isinstance(event, ChildStarted) and is_observer(event):
        return 0, ""
    agent = (
        event.session_id
        if isinstance(event, SessionStarted)
        else event.child_session_id
    )
    name = "SessionStart" if isinstance(event, SessionStarted) else "SubagentStart"
    if _place(cwd, ctx.root) is None:
        ctx.journal(agent, name, (), Verdict.NOT_MET, _OUTSIDE)
        return 0, ""
    if isinstance(event, SessionStarted):
        state, _ = bind_lead(ctx.state, ctx.manifest, event.session_id, ctx.now)
        if state is not ctx.state:
            ctx.save(state)
        return 0, ""
    state, why = start_child(ctx.state, ctx.manifest, event, ctx.now)
    if state is not ctx.state:
        ctx.save(state)
    verdict = Verdict.MET if why.startswith("ok:") else Verdict.NOT_MET
    ctx.journal(agent, name, (), verdict, why)
    return 0, ""


def _pinned(argv: list[str]) -> tuple[Path, Path]:
    parser = argparse.ArgumentParser(prog="mandate-hook", add_help=False)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--root", required=True)
    args = parser.parse_args(argv)
    dirs = (Path(args.state_dir), Path(args.root))
    for path in dirs:
        if not path.is_absolute() or not path.is_dir():
            raise ValueError("mandate-hook needs absolute existing directories")
    state_dir, root = (path.resolve() for path in dirs)
    if state_dir == root or state_dir.is_relative_to(root):
        raise ValueError("mandate-hook state dir must live outside the root")
    return dirs


def cli() -> None:
    """Console entry point: `mandate-hook --state-dir <ABS> --root <ABS>`."""
    try:
        text = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        state_dir, root = _pinned(sys.argv[1:])
        code, out = main(
            text,
            int(time.time()),
            secrets.token_hex(16),
            state_dir,
            root,
            exposed=credential_exposed(os.environ),
        )
    except BaseException:  # noqa: BLE001
        code, out = 0, deny_output("malformed: mandate error")
    if out:
        sys.stdout.write(out)
    sys.exit(code)
