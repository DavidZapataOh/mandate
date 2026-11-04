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
| Voice intent | `muse-voice-transcribe-1.0` | Meta Model API | `swarm/voice.py` | `pytest -m live e2e/test_voice_live.py`; clips over 10 minutes or 31,000,000 bytes are refused before upload |
| Voice confirmation | `muse-voice-transcribe-1.0` | Meta Model API | `swarm/voice.py`, `swarm/server.py`, `webapp/app.js` | `pytest -m live e2e/test_voice_confirm_live.py` |
| Mandate MCP desk | `muse-spark-1.3` | Meta Model API, Muse Code | `swarm/server.py`, `swarm/mcp_bridge.py` | `pytest -m live e2e/test_mcp_live.py` |
| WebMCP approval | glasses assistant | Meta Web App | `webapp/app.js` | `pytest e2e/test_webapp.py` (headless Node and in-browser tests; not run on real glasses) |
| Intent drafting | `muse-spark-1.3` | Meta Model API | `swarm/intent.py` | `pytest -m live e2e/test_voice_live.py` |
| Console world plates and frames | `muse-image-1.0` | Meta Model API (images) | `console/tools/muse_image.ts`, `console/tools/assets.json` | `cd console && npx vitest run tools/muse_image.test.ts` (request shape, offline); every plate's request id is in `console/tools/assets.json` and embedded in its PNG |

Once the holder copy of the receipt exists (the proof explorer will serve it and will carry the salt; it is not built yet), recompute the certified hash with `printf '%s' '<canonical action JSON>' | openssl dgst -sha256 -mac HMAC -macopt hexkey:<action salt hex>`; the digest must equal the certificate's `action_hash`.

Live tests are opt-in and need `MODEL_API_KEY` or `META_API_KEY`, plus `BASETEN_API_KEY` for the attacker row and a logged-in `muse` CLI for the swarm row.

The Mandate desk (`mandate-desk`) serves quote, status, confirm and receipt tools over MCP. Spark reaches it through an app-side bridge (`swarm/mcp_bridge.py`) because the Meta Responses API has no remote-MCP tool; Muse Code connects directly through `mcpServers`. Confirming a payment needs the holder's signed consent, which the gate verifies and consumes once. WebMCP runs on the glasses only in Developer Mode or rollout, and the glasses assistant can list and show a payment but cannot approve it: only the holder's tap on Approve signs.

To run the desk locally, start `mandate-desk` (after `pip install -e .`). It prints one line, `Pair the holder device: http://127.0.0.1:8765/app/#pair=<token>`. Open that URL once on the approving device: the page registers its holder key with the one-time token and removes it from the address bar. Later visits use `http://127.0.0.1:8765/app/`. The `/api` and `/app` routes accept only `127.0.0.1` and `localhost` as Host; pass `--public-host <name>` to add the name of an HTTPS proxy in front of the desk.

While a payment waits, the console's holder approval panel shows the seven consent fields the holder's device signs, the sha256 of those bytes (the holder page shows the same grouped hash under `Consent hash`), the paired device (`GET /api/device`, also shown on the holder page as `This device <fingerprint>`), and the outcome through to the booth. The console holds no key and cannot approve. Verify with `cd console && npm run e2e`; the panel's states (refused, expired, approved, paid, gate mismatch, denied, desk unreachable, no WebCrypto, replay) are captured by `console/e2e/approval-states.spec.ts` with `CAPTURE=1 npx playwright test e2e/approval-states.spec.ts`.

With `--voice` (on `mandate-desk` or `mandate-console`), the holder page can record a spoken confirmation: tap `Speak to confirm`, say the payment, tap `Stop`. The desk forwards the clip once to Muse Voice Transcribe and returns only the words, which the page shows under the seven consent fields with the line `Voice is a confirmation, not proof of who spoke. Only your Approve tap signs, on this device.` The desk transcribes only a clip the paired device signed (`x-mandate-voice-sig`), keeps no audio and never signs; the words never enable or block Approve. The microphone needs https or localhost. The desk reports on `GET /api/device` whether `--voice` is on; with it off the page hides `Speak to confirm` and never asks for the microphone. Each signed clip is transcribed once per pending quote, a quote past its deadline is refused, and a second upload is refused before its body is read.

The reasoning anchor (`swarm/anchor.py`, checked by `e2e/test_anchor_live.py`) binds a certificate to the model, response id and encrypted reasoning that Meta returned, so it proves non-substitution after issuance; Meta Model API does not authenticate replayed encrypted reasoning, so it does not prove that Meta re-verified the reasoning. The attacker row counts as open weights only when its recorded provider reads `baseten`; an attacker that fell back to the Meta Model API is labeled `meta-fallback`. The attacker model fills the parameters of seven fixed attack templates, and each plan is applied deterministically through the real defense layer it targets.

The console shows what the gate decides as it happens. Build it with `cd console && npm ci && npm run build`, then run `mandate-console` (after `pip install -e .`); it prints the pairing URL and `Console: http://127.0.0.1:8766/console/`. `POST /api/attack {"kind": ...}` runs one of seven pinned template attacks (no model call), and the ledger labels it `TEMPLATE`. `--journal <state-dir>/journal.jsonl` streams Muse Code hook decisions into the same ledger. `--record run.jsonl` captures the stream of one process; use a fresh file per run, because a capture whose line numbers start over is refused. A capture copied to `console/public/replay/<name>.jsonl` plays at `/console/?replay=<name>` under a permanent `REPLAY` label after `npm run build` and a restart of `mandate-console`, which serves the build it found at startup. Verify with `cd console && npm run e2e`.

The ATTACK button in the top bar opens the attack panel. It has seven pinned template attacks (labelled `TEMPLATE`; the same press runs the same attack and is denied with zero cents moved); the seventh forges the holder's approval, signed by a key that is not the paired holder's, and dies at the gate's consent check), and the three Nimbus deploy steps (labelled `SCENARIO`). `mandate-console --live-attacker` also enables a control that asks an open-weights model to plan the attack; it is off by default, needs `BASETEN_API_KEY`, and otherwise falls back to the Meta API with `MODEL_API_KEY` or `META_API_KEY`, labelled as not open weights. Without the flag the control is disabled and says so. Opening the forensic drawer of a denied line offers KILL-CAM, a tape that replays step by step which check refused it; it is rebuilt from the line's forensic record and nothing is run again.

`POST /api/deploy {"step": "release" | "poisoned_tool" | "stale_migration"}` runs one pinned Nimbus step through the gate, the MCP proxy and a simulated prod-eu target (no model call). The console's right-hand world shows Nimbus HQ for deploy and Muse Code hook lines and the bank for payment lines, and the BRANCH / NIMBUS HQ toggle shows either while the booth is idle.

## Architecture
See [ARCHITECTURE.md](ARCHITECTURE.md).

## License
MIT. See [LICENSE](LICENSE).
