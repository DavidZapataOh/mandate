// Test data only: the seven template denials as the server publishes them; the bundle gate fails the build if it ships.
import { ATTACK, CONFIRM, DEPLOY, patch } from "../../wire/__fixtures__/lines";
import { parseLine } from "../../wire/parse";
import type { ConsoleLine } from "../../wire/types";

const SWAP = JSON.parse(ATTACK);
const NONCE = "atk00000000000000000000000000003";
// The hashes are the gate's salted action hashes (HMAC-SHA256 under the press salt bytes([0xa3]) * 32 for nonce atk00000000000000000000000000003, the forged approval included, and bytes([0xdb]) * 32 for the Nimbus stale migration at dep00000000000000000000000000011; the poisoned tool keeps the MCP proxy's unsalted SHA-256).
const LEGIT_HASH = "20fa07c63133f7b15e26cebafeecff3f7bbdd4c61ee311b81ec8aa42e1dc8868";
const INFLATE_HASH = "b7df0f538186d50487f61c22718995525d0e69e18dae56694359292f9b43a471";
const FORGED_HASH = "083d5271bec37350a77e45db957a3e65a0fe00d7413fa4f2dc2999502ee8fd8d";
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
  bank: null,
};

const attack = (kind: string, layer: string, reason: string, top: Record<string, unknown>): string =>
  patch(ATTACK, top, { attack: kind, layer, reason, narrative: `MANDATE_FIXTURE ${kind}` });

export const DENIALS: Readonly<Record<string, string>> = {
  payee_swap: ATTACK,
  amount_inflate: attack("amount_inflate", "model->gate", "amount differs from intent", {
    event: { ...SWAP.event, action: INFLATE_HASH, reason: "amount differs from intent" },
    forensic: { ...SWAP.forensic, cava: cava("2000000", "acme-991"), action_hash: INFLATE_HASH },
  }),
  replay: attack("replay", "bank", "replay: jti consumed", {
    event: null,
    forensic: {
      ...certified,
      bank: {
        rail: "simulated",
        provider: null,
        transfer_id: "pay:000001",
        status: "complete",
        idempotency_key: "mandate-cert-atk00000000000000000000000000003",
      },
    },
  }),
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
const STALE_HASH = "f960d447b69f99f31b0f80708cede65fb4a9dfe2c78f1f45281acf1235095762";

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
      bank: null,
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
