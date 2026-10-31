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
TODO: every simplification or fallback is labeled here with its location.
