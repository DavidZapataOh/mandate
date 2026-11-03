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
- Muse Code subagent scope (swarm/hook.py): authority (manifest, state, keys, journal) lives outside the governed workspace and is pinned via the hook's argv (`mandate-hook --state-dir <abs> --root <abs>`); nothing under the repo is read as authority, event cwds must be the repo root or a worktree under `.muse/worktrees/`, and file-tool writes under `.mandate/` and `.muse/` are refused and shell tokens (including fragments split at every `=` and `:`) that name `.muse` or `.mandate` or escape the worktree are refused, which also denies URLs in shell commands (fail closed). Read tools may still read `.muse/` and `.mandate/` inside the worktree, since authority lives outside it. File atoms are checked exactly, shell atoms only by the first binary of each command segment, and token checks do not see paths that an executed program constructs; code executed by an allowed binary (pytest, git) is contained by Muse Code's OS sandbox and worktree isolation, not by Mandate.
- Red-team attacker (swarm/redteam.py, swarm/attacker.py): the model fills the parameters of six fixed attack templates; each plan is applied deterministically through the real defense layer it targets. Replay takes no parameters, and the scope-escalation and MCP-exfil kinds are checked at their own layer without touching the bank.
- Holder consent (gate/consent.py): when a rule sets `consent_required`, the gate verifies an Ed25519 signature over pinned bytes binding amount, currency, payee, reference, debit account, nonce and expiry, and consumes the consent once. Voice intents (swarm/intent.py) are signed but are not yet gate-verified consents. The holder key is provisioned once: `mandate-desk` prints a one-time pairing token locally, and `POST /api/holder` registers a key only with that token, which is spent on first use; a restart issues a new token and forgets the holder. The `/api` and `/app` routes refuse a Host outside `127.0.0.1`, `localhost` and any `--public-host` names, so a DNS-rebound page cannot drive them. Desk state is in memory, and revocation indices wrap at 1024.
- Console (swarm/console.py, console/): attacks started from the console are deterministic templates and are labeled `TEMPLATE`; the replay template pays the legitimate 200.00 once per click before replaying its certificate. Console state is in memory and line numbers restart with each process, so clients restart from zero when the stream announces a new epoch. The journal tail publishes only hook records under the `hook` source; anything else in the journal, including a console line claiming another source, is skipped. Replay mode (`?replay=<name>`) plays a recorded stream and says `REPLAY` for as long as it is active.
- Spawn binding assumes children are created only through subagent_spawn: SubagentStart carries no parent id, so the next UUID child claims the single pending spawn.
