# Mandate Architecture

## Decisions
TODO: record each architectural decision with date and rationale.

## Invariants (non-negotiable)
1. Enforce at the execution boundary (gate + resource server), never in the prompt.
2. The agent never holds the mother credential — only ephemeral, strictly-scoped delegations.
3. The agent never enters the bank session; humans prove state client-side; the agent sees receipts only.
4. Total determinism on the decision path; no LLM votes in the gate; uncheckable input yields NOT CHECKABLE, never a guess.
5. Everything verifiable by third parties without exposing secrets.
6. Zero honeypot: store receipts and hashes only — never statements, sessions, or secrets.

## Threat model
TODO: principals, trust boundaries, and out-of-scope threats.

## Honest seams
- Reasoning anchor (swarm/anchor.py): binds a certificate to the model, response id and encrypted reasoning that Meta returned. Meta Model API does not authenticate replayed encrypted reasoning, so the anchor proves non-substitution after issuance, not that Meta re-verified the reasoning.
- Muse Code subagent scope (swarm/hook.py): authority (manifest, state, keys, journal) lives outside the governed workspace and is pinned via the hook's argv (`mandate-hook --state-dir <abs> --root <abs>`); nothing under the repo is read as authority, event cwds must be the repo root or a worktree under `.muse/worktrees/`, and `.mandate/` and `.muse/` paths are never writable. File atoms are checked exactly, shell atoms only by the first binary of each command segment; code executed by an allowed binary (pytest, git) is contained by Muse Code's OS sandbox and worktree isolation, not by Mandate.
- Spawn binding assumes children are created only through subagent_spawn: SubagentStart carries no parent id, so the next UUID child claims the single pending spawn.
