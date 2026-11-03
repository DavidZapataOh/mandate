# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Strict TypeScript + Vite; Vitest for unit tests and Playwright for browser tests; Canvas 2D for the pixel-art scenes; the Rive web runtime for the seal and character animation; generated imagery via Higgsfield. No UI framework. Served by the Python desk process alongside the existing `webapp/` approval page.

## Users

- **Primary viewer of the console: a judge or first-time spectator** watching the live demo or the three-minute video. They do not know Mandate; they must understand what an agent tried, what the gate decided and why, at a glance.
- **Valeria — platform/DevOps lead** running fleets of coding and deploy agents with real production access. Highly technical; verifies by reading code and measuring latency herself. Served by forensic mode and the explorer.
- **Marcos — CISO / head of platform**, the buyer. Needs a defensible posture and an executive view. Served by Command.
- **A bank's risk and fraud team** (hero case) and **the account holder**, who approves payments on their own device (Ray-Ban Display or browser).
- **Andrés — auditor, insurer or counterparty** who verifies a receipt without an account or secrets. Served by the explorer.

## Product Purpose

Mandate is a cryptographic authorization gate between AI agents and banks: an agent's proposed action is canonicalized, checked against policy and the human's signed intent or consent, and only then receives a single-use certificate the bank verifies before moving money. Every decision is recorded in a Merkle registry. The console makes that real system visible live; success is a viewer seeing an attack die in the gate and a legitimate payment pass, with every claim checkable.

## Positioning

The gate verifies, it does not trust: Meta's agents (Muse Spark, Muse Code, open-weights attackers) act through it, the holder's Ed25519 consent is checked at the gate itself and consumed once, and anyone can re-verify a receipt offline. Every verdict, number and hash on screen comes from a real gate event; ambient motion, kill-cam playback, recorded replays and pinned scenarios are labelled as such.

## Operating Context

Live demo and recorded video for the Meta hackathon (Indie track); a presenter or judge presses attack buttons live; the console runs next to the MCP desk, Muse Code fan-out and the WebMCP glasses approval page. Evidence comes from the gate's decision events, certificates, registry proofs and reasoning anchors.

## Capabilities and Constraints

- Real today (in this repo): CAVA canonicalization, policy with intent binding, Ed25519 JWS certificates, single-use and revocation, bank verifier, broker delegations, Merkle registry with anchors, reasoning anchor, governed Muse Code fan-out via hooks, open-weights red team, per-decision Meta attribution, voice intent, gate-verified holder consent, MCP desk, WebMCP approval page.
- Constraints: zero mock rows in shipped paths (replay of a recorded real stream is the only fallback); every displayed fact traceable to a real event or artifact; English-only code and copy in the repo.
- Undecided: final deploy host for public HTTPS.

## Brand Commitments

The Mandate brand book (v2.0) is binding: name Mandate, tagline "Don't trust agents. Verify them.", dark-first Ink `#0B0D10` / Bone `#F6F4EE`, Verify `#1FD598` reserved for verified states only, the Reunion mark, "dark security + pixel soul" world, Inter + JetBrains Mono.

## Evidence on Hand

Real gate decision events, certificates, registry inclusion proofs, live Meta call traces (model, response id, request id), demo bills (`demo/bills/`), voice clip (`demo/voice/`), live test runs. No customers, testimonials, benchmarks beyond measured ones, or third-party endorsements exist; never fabricate them.

## Product Principles

1. Show, then prove: every friendly bubble opens into the exact forensic object behind it.
2. Green means verified, nothing else.
3. Denials are the hero moment: an attack dying in the gate must be the most legible thing on screen.
4. Honest seams stay visible: what is simulated or trust-on-first-use is labeled, never hidden.

## Accessibility & Inclusion

Readable at video resolution and from a projector; motion respects `prefers-reduced-motion`; information never conveyed by color alone (pass/deny also carry text and shape).
