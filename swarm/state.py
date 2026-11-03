"""Mandate-owned swarm state: manifest, lead binding, pending spawn, child links."""

import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from gate.broker import Delegation, Scope, mint
from gate.certs import generate_keypair
from swarm.hookio import ChildStarted

TTL_S = 3600
PENDING_TTL_S = 60
_LEAD = "lead"


def _scope(raw: dict[str, Any]) -> Scope:
    return Scope(tuple(raw["atoms"]), int(raw["max_spend_cents"]))


def _strictly_inside(scope: Scope, parent: Scope) -> bool:
    atoms, parent_atoms = set(scope.atoms), set(parent.atoms)
    return (
        atoms <= parent_atoms
        and scope.max_spend_cents <= parent.max_spend_cents
        and (atoms < parent_atoms or scope.max_spend_cents < parent.max_spend_cents)
    )


@dataclass(frozen=True)
class SwarmManifest:
    """Human-written roles, each strictly inside the root scope."""

    root: Scope
    roles: dict[str, Scope]

    @classmethod
    def load(cls, path: Path) -> "SwarmManifest":
        """Read and validate a manifest file.

        Raises:
            ValueError: No lead role, or a role not strictly inside root.
        """
        raw = json.loads(path.read_text())
        root = _scope(raw["root"])
        roles = {name: _scope(value) for name, value in raw["roles"].items()}
        if _LEAD not in roles:
            raise ValueError("manifest needs a lead role")
        for name, scope in roles.items():
            if not _strictly_inside(scope, root):
                raise ValueError(f"role exceeds root: {name}")
        return cls(root, roles)


@dataclass(frozen=True)
class AgentRecord:
    role: str
    pub: bytes
    priv: bytes
    chain: tuple[Delegation, ...]


@dataclass(frozen=True)
class PendingSpawn:
    parent: str
    role: str
    at: int


@dataclass(frozen=True)
class SwarmState:
    root_pub: bytes
    root_priv: bytes
    lead: str | None = None
    agents: dict[str, AgentRecord] = field(default_factory=dict)
    pending: PendingSpawn | None = None


def new_state() -> SwarmState:
    """Fresh state with a new root keypair."""
    priv, pub = generate_keypair()
    return SwarmState(root_pub=pub, root_priv=priv)


def _link_to_json(link: Delegation) -> dict[str, Any]:
    return {
        "v": link.v,
        "child_pub": link.child_pub.hex(),
        "scope": {
            "atoms": list(link.scope.atoms),
            "max_spend_cents": link.scope.max_spend_cents,
        },
        "expires_at": link.expires_at,
        "parent_ref": link.parent_ref,
        "revocation_index": link.revocation_index,
        "signature": link.signature.hex(),
    }


def _link_from_json(raw: dict[str, Any]) -> Delegation:
    return Delegation(
        v=raw["v"],
        child_pub=bytes.fromhex(raw["child_pub"]),
        scope=_scope(raw["scope"]),
        expires_at=raw["expires_at"],
        parent_ref=raw["parent_ref"],
        revocation_index=raw["revocation_index"],
        signature=bytes.fromhex(raw["signature"]),
    )


def save_state(state: SwarmState, path: Path) -> None:
    """Write state as JSON via a temp file and atomic replace."""
    body = {
        "root_pub": state.root_pub.hex(),
        "root_priv": state.root_priv.hex(),
        "lead": state.lead,
        "agents": {
            key: {
                "role": rec.role,
                "pub": rec.pub.hex(),
                "priv": rec.priv.hex(),
                "chain": [_link_to_json(link) for link in rec.chain],
            }
            for key, rec in state.agents.items()
        },
        "pending": None
        if state.pending is None
        else {
            "parent": state.pending.parent,
            "role": state.pending.role,
            "at": state.pending.at,
        },
    }
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(json.dumps(body))
    os.replace(tmp, path)


def load_state(path: Path) -> SwarmState:
    """Read state written by `save_state`."""
    raw = json.loads(path.read_text())
    agents = {
        key: AgentRecord(
            role=value["role"],
            pub=bytes.fromhex(value["pub"]),
            priv=bytes.fromhex(value["priv"]),
            chain=tuple(_link_from_json(link) for link in value["chain"]),
        )
        for key, value in raw["agents"].items()
    }
    pending = raw["pending"]
    return SwarmState(
        root_pub=bytes.fromhex(raw["root_pub"]),
        root_priv=bytes.fromhex(raw["root_priv"]),
        lead=raw["lead"],
        agents=agents,
        pending=None if pending is None else PendingSpawn(**pending),
    )


def bind_lead(
    state: SwarmState, manifest: SwarmManifest, session_id: str, now: int
) -> tuple[SwarmState, str]:
    """Bind the lead session once, with a single link minted by root."""
    if state.lead is not None:
        return state, "lead: already bound"
    priv, pub = generate_keypair()
    scope = manifest.roles[_LEAD]
    link = mint(
        state.root_priv, state.root_pub, pub, scope, manifest.root, now + TTL_S, 0
    )
    record = AgentRecord(_LEAD, pub, priv, (link,))
    agents = {**state.agents, session_id: record}
    return replace(state, lead=session_id, agents=agents), "ok: lead bound"


def request_spawn(
    state: SwarmState,
    manifest: SwarmManifest,
    caller: str,
    role: str,
    isolated: bool,
    now: int,
) -> tuple[SwarmState, bool, str]:
    """Record one pending spawn if the caller may delegate the role."""
    pending = state.pending
    if pending is not None and now - pending.at > PENDING_TTL_S:
        state = replace(state, pending=None)
    parent = state.agents.get(caller)
    if parent is None:
        return state, False, "scope: agent has no delegation"
    scope = manifest.roles.get(role)
    if scope is None:
        return state, False, f"spawn: unknown role {role}"
    if not isolated:
        return state, False, "spawn: worktree isolation required"
    if state.pending is not None:
        return state, False, "spawn: previous spawn pending"
    if not _strictly_inside(scope, parent.chain[-1].scope):
        return state, False, "scope: role not inside parent"
    pending = PendingSpawn(caller, role, now)
    return replace(state, pending=pending), True, f"ok: spawn pending {role}"


def start_child(
    state: SwarmState, manifest: SwarmManifest, child: ChildStarted, now: int
) -> tuple[SwarmState, str]:
    """Mint the pending role's link for a started child session."""
    pending = state.pending
    if pending is not None and now - pending.at > PENDING_TTL_S:
        state = replace(state, pending=None)
        pending = None
    parent = None if pending is None else state.agents.get(pending.parent)
    if pending is None or parent is None:
        return state, "spawn: no pending spawn"
    if child.child_session_id in state.agents:
        return state, "spawn: agent already bound"
    priv, pub = generate_keypair()
    try:
        link = mint(
            parent.priv,
            parent.pub,
            pub,
            manifest.roles[pending.role],
            parent.chain[-1].scope,
            now + TTL_S,
            len(state.agents),
        )
    except (ValueError, KeyError):
        return replace(state, pending=None), "scope: role not inside parent"
    record = AgentRecord(pending.role, pub, priv, (*parent.chain, link))
    agents = {**state.agents, child.child_session_id: record}
    return (
        replace(state, agents=agents, pending=None),
        f"ok: minted {pending.role}",
    )
