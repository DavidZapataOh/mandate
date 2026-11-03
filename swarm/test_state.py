import json
import os
import stat

import pytest

from gate.broker import verify_chain
from gate.certs import BitstringRevocation
from swarm.hookio import ChildStarted
from swarm.state import (
    SwarmManifest,
    bind_lead,
    load_state,
    new_state,
    request_spawn,
    save_state,
    start_child,
)

NOW = 1800000000
CHILD = ChildStarted("01a19f76-4b91-7342-b01f-75765e69d6bb", "child-1")
MANIFEST = {
    "root": {
        "atoms": ["file:README.md", "file:app.py", "file:deploy.env", "cmd:ls"],
        "max_spend_cents": 0,
    },
    "roles": {
        "lead": {
            "atoms": ["file:README.md", "file:app.py", "cmd:ls"],
            "max_spend_cents": 0,
        },
        "docs": {"atoms": ["file:README.md", "cmd:ls"], "max_spend_cents": 0},
    },
}


def _manifest(tmp_path, raw=MANIFEST):
    path = tmp_path / "swarm.json"
    path.write_text(json.dumps(raw))
    return SwarmManifest.load(path)


def _lead(tmp_path):
    manifest = _manifest(tmp_path)
    state, reason = bind_lead(new_state(), manifest, "lead-1", NOW)
    assert reason == "ok: lead bound"
    return manifest, state


def test_manifest_requires_lead_and_containment(tmp_path):
    no_lead = {"root": MANIFEST["root"], "roles": {"docs": MANIFEST["roles"]["docs"]}}
    with pytest.raises(ValueError, match="manifest needs a lead role"):
        _manifest(tmp_path, no_lead)
    wide = dict(MANIFEST, roles=dict(MANIFEST["roles"], ops=MANIFEST["root"]))
    with pytest.raises(ValueError, match="role exceeds root: ops"):
        _manifest(tmp_path, wide)


def test_lead_binds_once(tmp_path):
    manifest, state = _lead(tmp_path)
    assert state.lead == "lead-1"
    _, reason = bind_lead(state, manifest, "other", NOW)
    assert reason == "lead: already bound"


def test_spawn_then_child_minted_inside_parent(tmp_path):
    manifest, state = _lead(tmp_path)
    state, ok, reason = request_spawn(state, manifest, "lead-1", "docs", True, NOW)
    assert (ok, reason) == (True, "ok: spawn pending docs")
    state, reason = start_child(state, manifest, CHILD, NOW + 1)
    assert reason == "ok: minted docs"
    record = state.agents["child-1"]
    assert record.role == "docs"
    assert sorted(record.chain[-1].scope.atoms) == ["cmd:ls", "file:README.md"]
    assert verify_chain(
        record.chain, state.root_pub, manifest.root, NOW + 2, BitstringRevocation()
    ) == (True, "ok: chain valid")
    assert state.pending is None


@pytest.mark.parametrize(
    ("caller", "role", "isolated", "reason"),
    [
        ("stranger", "docs", True, "scope: agent has no delegation"),
        ("lead-1", "ops", True, "spawn: unknown role ops"),
        ("lead-1", "docs", False, "spawn: worktree isolation required"),
        ("lead-1", "lead", True, "scope: role not inside parent"),
    ],
)
def test_spawn_refusals(tmp_path, caller, role, isolated, reason):
    manifest, state = _lead(tmp_path)
    _, ok, got = request_spawn(state, manifest, caller, role, isolated, NOW)
    assert (ok, got) == (False, reason)


def test_second_pending_spawn_denied(tmp_path):
    manifest, state = _lead(tmp_path)
    state, _, _ = request_spawn(state, manifest, "lead-1", "docs", True, NOW)
    _, ok, reason = request_spawn(state, manifest, "lead-1", "docs", True, NOW + 5)
    assert (ok, reason) == (False, "spawn: previous spawn pending")
    _, ok, reason = request_spawn(state, manifest, "lead-1", "docs", True, NOW + 61)
    assert (ok, reason) == (True, "ok: spawn pending docs")


def test_child_without_pending_spawn_gets_nothing(tmp_path):
    manifest, state = _lead(tmp_path)
    state, reason = start_child(state, manifest, CHILD, NOW)
    assert reason == "spawn: no pending spawn"
    assert "child-1" not in state.agents


def test_state_roundtrip_is_atomic(tmp_path):
    manifest, state = _lead(tmp_path)
    state, _, _ = request_spawn(state, manifest, "lead-1", "docs", True, NOW)
    path = tmp_path / ".mandate" / "state.json"
    path.parent.mkdir()
    save_state(state, path)
    assert load_state(path) == state
    assert sorted(p.name for p in path.parent.iterdir()) == ["state.json"]


def test_stale_pending_cannot_be_claimed(tmp_path):
    manifest, state = _lead(tmp_path)
    state, _, _ = request_spawn(state, manifest, "lead-1", "docs", True, NOW)
    state, reason = start_child(state, manifest, CHILD, NOW + 61)
    assert reason == "spawn: no pending spawn"
    assert "child-1" not in state.agents
    assert state.pending is None


def test_start_child_role_removed_from_manifest(tmp_path):
    manifest, state = _lead(tmp_path)
    state, _, _ = request_spawn(state, manifest, "lead-1", "docs", True, NOW)
    roles = {"lead": MANIFEST["roles"]["lead"]}
    shrunk = _manifest(tmp_path, dict(MANIFEST, roles=roles))
    state, reason = start_child(state, shrunk, CHILD, NOW + 1)
    assert reason == "scope: role not inside parent"
    assert state.pending is None
    assert "child-1" not in state.agents


def test_state_file_is_private(tmp_path):
    _, state = _lead(tmp_path)
    path = tmp_path / "state.json"
    save_state(state, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_child_cannot_rebind_existing_session(tmp_path):
    manifest, state = _lead(tmp_path)
    lead_pub = state.agents["lead-1"].pub
    state, _, _ = request_spawn(state, manifest, "lead-1", "docs", True, NOW)
    clash = ChildStarted("01a19f76-4b91-7342-b01f-75765e69d6bb", "lead-1")
    state, reason = start_child(state, manifest, clash, NOW + 1)
    assert reason == "spawn: agent already bound"
    assert state.agents["lead-1"].pub == lead_pub
    assert state.pending is not None


def test_state_file_private_even_with_stale_tmp(tmp_path):
    _, state = _lead(tmp_path)
    path = tmp_path / "state.json"
    tmp = tmp_path / "state.json.tmp"
    tmp.write_text("stale")
    os.chmod(tmp, 0o644)
    save_state(state, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not tmp.exists()
