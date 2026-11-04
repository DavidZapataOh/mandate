// Test data only; the bundle gate fails the build if this marker ships.
import { ATTACK, BANK, CONFIRM, DEPLOY, patch, SANDBOX_CONFIRM } from "../../wire/__fixtures__/lines";
import { parseLine } from "../../wire/parse";
import type { Attribution, ConsoleLine } from "../../wire/types";

const confirm = JSON.parse(CONFIRM);
const attack = JSON.parse(ATTACK);

const CODE: Attribution = {
  provider: "muse-code", model: "muse-spark-1.3", response_id: null, request_id: "toolu_fixture_07",
  latency_ms: null, input_tokens: null, output_tokens: null, anchor: null,
};
const OPEN: Attribution = {
  provider: "baseten", model: "meta-models/muse-spark-open-1026", response_id: null, request_id: "rq-fixture-05",
  latency_ms: 812.0, input_tokens: null, output_tokens: null, anchor: null,
};
const SPARK: Attribution = {
  provider: "meta-model-api", model: "muse-spark-1.3", response_id: "resp_fixture_09", request_id: "req_fixture_09",
  latency_ms: 640.5, input_tokens: 1204, output_tokens: 96, anchor: "ab".repeat(32),
};

function hookLine(seq: number, verdict: "MET" | "NOT_MET", reason: string, lat_us: number): string {
  return JSON.stringify({
    v: 3, seq, source: "hook", meta: CODE, forensic: null,
    event: { ...attack.event, id: `evt:fixture-${seq}`, policy: "swarm", verdict, reason, lat_us },
    subject: { agent: "MANDATE_FIXTURE child-1", tool: "edit_file", targets: ["src/app.py"], tool_use_id: "toolu_fixture_07" },
  });
}

export function attackLine(seq: number, kind: string, layer: string, reason: string, meta: Attribution | null, blocked = true, moved = 0): string {
  return JSON.stringify({
    v: 3, seq, source: "attack", event: null, meta, forensic: null,
    subject: { attack: kind, layer, reason, blocked, moved_cents: moved, narrative: `MANDATE_FIXTURE ${kind}`, origin: meta === null ? "template" : "model" },
  });
}

/** Nine real-shaped lines: two holds, three verified, four denied, no breach. */
export const WINDOW: readonly string[] = [
  patch(CONFIRM, { seq: 1, event: null, forensic: null }, { step: "quote", status: "quoted", payment_id: null, reason: null }),
  patch(CONFIRM, { seq: 2, event: null, forensic: null }, { step: "approve", status: "approved", payment_id: null, reason: null }),
  CONFIRM,
  ATTACK,
  attackLine(5, "mcp_exfil", "mcp", "denied: server undeclared", OPEN),
  attackLine(6, "replay", "bank", "replay: jti consumed", null),
  hookLine(7, "MET", "rule swarm-edit satisfied", 12.0),
  hookLine(8, "NOT_MET", "scope: target outside delegation", 30.0),
  JSON.stringify({
    v: 3, seq: 9, source: "bill", meta: SPARK,
    event: { ...confirm.event, id: "evt:fixture-9", policy: "payments", reason: "rule pay-intent satisfied", lat_us: 90.0 },
    subject: { proposal_call_id: "call_fixture_9", summary: "MANDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) from checking-881", confirmation: "Paid.", report_error: null },
    forensic: { ...confirm.forensic, policy: { policy_id: "payments", rule_id: "pay-intent" }, consent: null, registry: null, anchor: "ab".repeat(32) },
  }),
];

/** An attack the bank let through: 20000.00 left the account. */
export const BREACH = attackLine(10, "amount_inflate", "model->gate", "ok: executed", null, false, 2000000);

/** An approval the agent signed with its own key, refused by the gate's consent check. */
export const FORGED = attackLine(18, "forged_approval", "holder->gate", "consent: bad signature", null);

/** A kind string carrying Markdown table syntax. */
export const PIPE_KIND = attackLine(11, "x|y", "mcp", "denied: server undeclared", null);

const deployEvent = JSON.parse(DEPLOY).event;

function step(seq: number, name: string, layer: string, reason: string, blocked: boolean): string {
  const event = { ...deployEvent, verdict: blocked ? "NOT_MET" : "MET", cert: null, reason, lat_us: 18.0 };
  return patch(DEPLOY, { seq, event }, { step: name, layer, reason, blocked });
}

function intent(seq: number, status: string, reason: string | null): string {
  return patch(CONFIRM, { seq, event: null, forensic: null }, { step: "intent", quote_id: null, status, payment_id: null, reason });
}

/** Nimbus steps and holder intents: one release, two refused steps, one refused and one signed intent. */
export const HQ: readonly string[] = [
  DEPLOY.replace('"seq":9', '"seq":12'),
  step(13, "poisoned_tool", "mcp", "denied: tool undeclared", true),
  step(14, "stale_migration", "gate", "no rule matches", true),
  intent(15, "denied", "intent: bad signature"),
  intent(16, "signed", null),
];

/** A stale migration the gate let through. */
export const DEPLOY_BREACH = step(17, "stale_migration", "gate", "ok: released", false);

/** A payment the sandbox bank moved, verified. */
export const SANDBOX_PAY = patch(SANDBOX_CONFIRM, { seq: 18 });

/** A sandbox payment the desk refused: no transfer, no bank record. */
export const SANDBOX_REFUSED = patch(
  CONFIRM,
  { seq: 19, forensic: { ...confirm.forensic, bank: null } },
  { status: "denied", payment_id: null, reason: "denied: insufficient funds" },
);

/** The bank's own event naming the sandbox payment's transfer id. */
export const BANK_REPORT = patch(BANK, { seq: 20 }, { object_id: "sandbox_account_transfer_MANDATE_FIXTURE" });

/** A bank event naming an object no payment in the window carries. */
export const BANK_OTHER = patch(
  BANK,
  { seq: 21 },
  {
    event_id: "sandbox_event_MANDATE_FIXTURE_2",
    category: "inbound_ach_transfer.created",
    object_type: "inbound_ach_transfer",
    object_id: "sandbox_inbound_ach_transfer_MANDATE_FIXTURE",
    summary: "MANDATE_FIXTURE Inbound ACH transfer created",
  },
);

export function lines(texts: readonly string[]): ConsoleLine[] {
  return texts.map(parseLine);
}
