# Mandate

> Don't trust agents. Verify them.

Mandate is the independent authorization and verification layer between AI
agents and the world: no action touches money, data, or production without
a valid cryptographic certificate. No certificate, no execution.

## Demo
TODO: link the live demo and the 3-minute video.

## What was built during the event
Built for the Meta Global AI Developer Hackathon × Cerebral Valley
(27 Oct – 4 Nov 2026). Every commit in this repo is event work; nothing
predates it.

## Quickstart
TODO: install and first governed run (lands with the SDK).

## How to verify
Each row maps a Meta model to its role, provider, source file and the command that exercises it. Run commands from the repository root.

| Role | Model | Provider | File | Verify |
|---|---|---|---|---|
| Bill-paying agent | `muse-spark-1.3` | Meta Model API | `swarm/agent.py`, `swarm/flow.py` | `pytest -m live e2e/test_agent_live.py` |
| Swarm lead | `muse-wonder-1.0` | Muse Code | `swarm/hook.py`, `demo/swarm_repo/` | `pytest -m live e2e/test_swarm_live.py` |
| Red-team attacker | `meta-models/muse-spark-open-1026` | Baseten | `swarm/attacker.py`, `swarm/redteam.py` | `pytest -m live e2e/test_redteam_live.py` |
| Voice intent | `muse-voice-transcribe-1.0` | Meta Model API | `swarm/voice.py` | `pytest -m live e2e/test_voice_live.py` |
| Intent drafting | `muse-spark-1.3` | Meta Model API | `swarm/intent.py` | `pytest -m live e2e/test_voice_live.py` |

Live tests are opt-in and need `MODEL_API_KEY` or `META_API_KEY`, plus `BASETEN_API_KEY` for the attacker row and a logged-in `muse` CLI for the swarm row.

The reasoning anchor (`swarm/anchor.py`, checked by `e2e/test_anchor_live.py`) binds a certificate to the model, response id and encrypted reasoning that Meta returned, so it proves non-substitution after issuance; Meta Model API does not authenticate replayed encrypted reasoning, so it does not prove that Meta re-verified the reasoning. The attacker row counts as open weights only when its recorded provider reads `baseten`; an attacker that fell back to the Meta Model API is labeled `meta-fallback`. The attacker model fills the parameters of six fixed attack templates, and each plan is applied deterministically through the real defense layer it targets.

## Architecture
See [ARCHITECTURE.md](ARCHITECTURE.md).

## License
MIT. See [LICENSE](LICENSE).
