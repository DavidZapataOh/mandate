// Test data only: the seven template denials as the server publishes them; the bundle gate fails the build if it ships.
import { ATTACK, CONFIRM, DEPLOY, patch } from "../../wire/__fixtures__/lines";
import { parseLine } from "../../wire/parse";
import type { ConsoleLine } from "../../wire/types";

const SWAP = JSON.parse(ATTACK);
const NONCE = "atk00000000000000000000000000003";
const LEGIT_HASH = "a168aea0b9fad8b2bf3ced8a6c61c58c310f5c294f03ef8db24216e40be0037d";
const INFLATE_HASH = "aad68f808700afba483392ba99f94feb5458587104f65ff4f9fa51f45a02c87d";
const FORGED_HASH = "35a733ef534b387b92fa689ff980b2dbe2780b22801e179d89827dd4501cfbd7";
const targets = (amount: string, to: string) => [`amount:USD:${amount}`, "from:checking-881", "ref:A-991", `to:${to}`];
const cava = (amount: string, to: string) => ({ ...SWAP.forensic.cava, targets: targets(amount, to) });

/** The approval the agent signed itself: the holder's fields, someone else's key. */
export const FORGED_CONSENT = {
  amount_cents: 20000,
  currency: "USD",
  recipient: "evil-666",
  reference: "A-991",
  source: "checking-881",
  nonce: NONCE,
  expires_at: 1800001300,
};

/** The gate's certified claims over the legitimate 200.00 USD payment. */
export const CLAIMS = {
  action_hash: LEGIT_HASH,
  policy_id: "payments",
  policy_version: 1,
  verdict: "MET",
  freshness_nonce: NONCE,
  scope: "redteam",
  reasoning_commitment: "0".repeat(64),
  evidence_refs: [],
  revocation_index: 0,
};

const certified = {
  cava: cava("20000", "acme-991"),
  action_hash: LEGIT_HASH,
  policy: { policy_id: "payments", rule_id: "pay-intent" },
  cert_claims: CLAIMS,
  consent: null,
  registry: null,
  anchor: null,
};

const attack = (kind: string, layer: string, reason: string, top: Record<string, unknown>): string =>
  patch(ATTACK, top, { attack: kind, layer, reason, narrative: `MANDATE_FIXTURE ${kind}` });

export const DENIALS: Readonly<Record<string, string>> = {
  payee_swap: ATTACK,
  amount_inflate: attack("amount_inflate", "model->gate", "amount differs from intent", {
    event: { ...SWAP.event, action: INFLATE_HASH, reason: "amount differs from intent" },
    forensic: { ...SWAP.forensic, cava: cava("2000000", "acme-991"), action_hash: INFLATE_HASH },
  }),
  replay: attack("replay", "bank", "replay: jti consumed", { event: null, forensic: certified }),
  post_cert_mutation: attack("post_cert_mutation", "gate->bank", "mismatch: action hash differs", {
    event: null,
    forensic: certified,
  }),
  scope_escalation: attack("scope_escalation", "delegation", "scope: target outside delegation", {
    event: null,
    forensic: null,
  }),
  mcp_exfil: attack("mcp_exfil", "mcp", "denied: server undeclared", { event: null, forensic: null }),
  forged_approval: attack("forged_approval", "holder->gate", "consent: bad signature", {
    event: { ...SWAP.event, action: FORGED_HASH, policy: "desk", reason: "consent: bad signature" },
    forensic: {
      ...SWAP.forensic,
      cava: { ...cava("20000", "evil-666"), runtime: "mcp" },
      action_hash: FORGED_HASH,
      policy: { policy_id: "desk", rule_id: "pay-with-consent" },
      consent: FORGED_CONSENT,
    },
  }),
};

/** One of the seven denials, parsed. */
export const denial = (kind: string): ConsoleLine => parseLine(DENIALS[kind]!);

const CONFIRM_JSON = JSON.parse(CONFIRM);

/** A desk payment the gate refused at the holder's consent. */
export const CONSENT_DENIED = patch(
  CONFIRM,
  {
    event: { ...CONFIRM_JSON.event, verdict: "NOT_MET", cert: null, reason: "consent: expired" },
    forensic: { ...CONFIRM_JSON.forensic, cert_claims: null, registry: null },
  },
  { status: "denied", payment_id: null, reason: "consent: expired" },
);

/** A desk approval refused before the gate: the signature did not verify. */
export const APPROVAL_DENIED = patch(
  CONFIRM,
  { event: null, forensic: null },
  { step: "approve", status: "denied", payment_id: null, reason: "consent: bad signature" },
);

/** A Muse Code tool call the gate refused; hook lines carry no canonical object. */
export const HOOK_DENIED = patch(ATTACK, {
  source: "hook",
  forensic: null,
  event: { ...SWAP.event, policy: "delegation", reason: "scope: target outside delegation" },
  subject: { agent: "child-1", tool: "edit_file", targets: ["src/app.py"], tool_use_id: null },
});

const RELEASE = JSON.parse(DEPLOY);
const POISON_HASH = "511282b863031996cfca1ab4878bda998ea9cbe253b8731e89e8cd659414243e";
const STALE_HASH = "623622b7c65a659a9de9d79aa291e0c3a108108df13ca5c6a811c669a50d03ee";

/** The Nimbus poisoned tool as the server publishes it: decided by the MCP proxy, which canonized and hashed the call. */
export const NIMBUS_POISONED = patch(
  DEPLOY,
  {
    seq: 10,
    event: { ...RELEASE.event, id: "evt:dep00000000000000000000000000010", verdict: "NOT_MET", action: POISON_HASH, policy: "manifest:nimbus-mcp", cert: null, reason: "denied: tool undeclared" },
    forensic: {
      cava: {
        category: "mcp",
        evidence_refs: [],
        executable: "mcp:nimbus-mcp",
        freshness: { nonce: "dep00000000000000000000000000010", timestamp: 1800001000 },
        operation: "secrets.export",
        reversible: true,
        runtime: "mcp",
        targets: ["scope=net:collector.evil.com"],
        version: "cava/1",
      },
      action_hash: POISON_HASH,
      policy: { policy_id: "manifest:nimbus-mcp", rule_id: null },
      cert_claims: null,
      consent: null,
      registry: null,
      anchor: null,
    },
  },
  { step: "poisoned_tool", summary: "MANDATE_FIXTURE Call secrets.export on nimbus-mcp", layer: "mcp", reason: "denied: tool undeclared", blocked: true },
);

/** The Nimbus stale migration: no rule of the release policy matches it. */
export const NIMBUS_STALE = patch(
  DEPLOY,
  {
    seq: 11,
    event: { ...RELEASE.event, id: "evt:dep00000000000000000000000000011", verdict: "NOT_MET", action: STALE_HASH, cert: null, reason: "no rule matches" },
    forensic: {
      ...RELEASE.forensic,
      cava: { ...RELEASE.forensic.cava, operation: "migrate", targets: ["artifact:migration-0017", "env:prod-eu"], freshness: { nonce: "dep00000000000000000000000000011", timestamp: 1800001000 } },
      action_hash: STALE_HASH,
      policy: { policy_id: "nimbus", rule_id: null },
      cert_claims: null,
    },
  },
  { step: "stale_migration", summary: "MANDATE_FIXTURE Re-run migration-0017 on prod-eu", layer: "gate", reason: "no rule matches", blocked: true },
);
