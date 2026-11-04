import { cueFor, type Outcome } from "../scene/cues";
import { railOf } from "../wire/rail";
import type { ConsoleLine } from "../wire/types";

export { railOf };

/** Attack kinds in display order; kinds outside this list follow in order of first appearance. */
export const ATTACK_KINDS: readonly string[] = [
  "payee_swap",
  "amount_inflate",
  "replay",
  "post_cert_mutation",
  "scope_escalation",
  "mcp_exfil",
  "forged_approval",
];

/** Deciding layers in display order; others follow in order of first appearance. */
export const LAYERS: readonly string[] = ["gate", "bank verifier", "broker", "MCP proxy", "holder approval", "holder intent", "desk"];

export interface Count {
  readonly count: number;
  readonly seqs: readonly number[];
}

export interface AttackRow {
  readonly kind: string;
  readonly attempts: number;
  readonly blocked: number;
  readonly breaches: number;
  readonly movedCents: number;
  readonly stoppedAt: readonly string[];
  readonly seqs: readonly number[];
}

export interface LayerRow {
  readonly layer: string;
  readonly denials: number;
  readonly kinds: readonly string[];
  readonly seqs: readonly number[];
}

export interface Posture {
  readonly window: { readonly first: number | null; readonly last: number | null; readonly lines: number };
  readonly decided: Count;
  readonly verified: Count;
  readonly denied: Count;
  /** Attack lines that were not blocked. */
  readonly breaches: Count;
  /** Nimbus scenario steps that ran when they should have been refused. */
  readonly stepsRan: Count;
  readonly movedCents: number;
  readonly attacks: readonly AttackRow[];
  readonly layers: readonly LayerRow[];
  readonly consent: { readonly certified: Count; readonly withConsent: Count };
  readonly latency: {
    readonly samples: number;
    readonly p50Us: number | null;
    readonly p95Us: number | null;
    readonly seqs: readonly number[];
  };
  readonly attribution: {
    readonly attributed: Count;
    readonly byProvider: readonly { readonly provider: string; readonly count: number }[];
  };
  /** Verified payments that carry a bank record, grouped by the rail named there. */
  readonly rails: readonly { readonly rail: string; readonly count: number; readonly seqs: readonly number[] }[];
}

export type MetricKey =
  | "decided" | "verified" | "denied" | "breaches" | "stepsRan" | "moved" | "consent" | "latency" | "attribution" | "attacks" | "layers" | "rails" | "unbacked";

export const LABELS: Readonly<Record<MetricKey, string>> = {
  decided: "Actions decided",
  verified: "Verified",
  denied: "Denied before execution",
  breaches: "Attacks not blocked",
  stepsRan: "Deploy steps that ran when they should not",
  moved: "Moved by attacks",
  consent: "Holder consent on certified payments",
  latency: "Gate decision time",
  attribution: "Decisions naming their model call",
  attacks: "Attacks by kind",
  layers: "Denials by layer",
  rails: "Payments by rail",
  unbacked: "Transfers at the bank without a certificate",
};

export const DEFINITIONS: Readonly<Record<MetricKey, string>> = {
  decided:
    "Lines in this window whose outcome is verified, denied or not blocked. Signed intents, quotes and approvals waiting for the holder, and bill reads that never reached the gate, are not decisions.",
  verified:
    "Desk payments the bank confirmed, Muse Code tool calls the gate allowed, bill payments whose gate verdict is MET, and pinned Nimbus releases the deploy target accepted.",
  denied:
    "Decisions refused before anything executed: denied or expired desk steps, Muse Code calls and bill payments the gate refused, attacks blocked at their layer with zero cents moved, Nimbus scenario steps refused at the MCP proxy or gate, and holder intents the desk refused.",
  breaches:
    "Attack lines whose layer did not return its expected denial, or that moved money. Each one is a failed defense and is never counted as verified. Nimbus scenario steps are counted separately.",
  stepsRan:
    "Nimbus scenario steps that should have been refused at the MCP proxy or the gate but ran. They are not attacks and are not in the attacks table; each is a failed defense and is never counted as verified.",
  moved:
    "Sum of the size of moved_cents over every attack line, each counted by absolute value so opposite moves never cancel: cents that left or entered the debited account during the attack step, measured from the bank balance before and after it.",
  consent:
    "Of the payments the gate certified in this window (gate verdict MET on a payments action), the share whose forensic record carries the holder's signed consent, which the gate verified and consumed once. Bill payments run under the holder's signed intent, not a per-payment consent, and count as without consent.",
  latency:
    "Time the deciding component spent on a decision (lat_us of the decision event) over every line with a decision event; nearest-rank p50 and p95. For desk, payment and Nimbus lines it is measured inside the gate; for Muse Code hook lines it is the whole hook run, including the wait for its state lock and its file reads and writes. Excludes model, network and bank time.",
  attribution:
    "Of the decisions in this window, the share whose line names the model call behind it (provider, model, request or response id). Template attacks, pinned Nimbus scenario steps and desk steps carry no model call and count as unattributed.",
  attacks:
    "One row per attack kind; attack lines only (Nimbus scenario steps count in the posture and the layers, not here). Attempts: attack lines of that kind. Blocked: the layer returned its pinned denial and zero cents moved. Stopped at: the layer that refused it.",
  layers:
    "Where each denial happened: the layer that refused the action (gate, bank verifier, broker, MCP proxy, holder approval, holder intent, desk).",
  rails:
    "Verified payments in this window grouped by the rail that moved the money, as each payment line names it (for example SANDBOX or SIMULATED).",
  unbacked:
    "Account transfers the bank itself lists from the desk's debit account since this registry began that carry no idempotency key naming a certificate this desk issued, or have no sealed execution entry in the registry. A read-only reconciler asks the bank's own API; 0 means every payment that left the account at the bank has a certificate and a receipt. Sealed payments the bank does not list are named in the evidence.",
};

const ATTACK_LAYERS: Readonly<Record<string, string>> = {
  "model->gate": "gate",
  "holder->gate": "gate",
  bank: "bank verifier",
  "gate->bank": "bank verifier",
  delegation: "broker",
  mcp: "MCP proxy",
};

const DEPLOY_LAYERS: Readonly<Record<string, string>> = { gate: "gate", mcp: "MCP proxy" };

/** The layer that decided a line. */
export function layerOf(line: ConsoleLine): string {
  switch (line.source) {
    case "attack":
      return ATTACK_LAYERS[line.subject.layer] ?? line.subject.layer;
    case "deploy":
      return DEPLOY_LAYERS[line.subject.layer] ?? line.subject.layer;
    case "hook":
    case "bill":
      return "gate";
    case "desk":
      switch (line.subject.step) {
        case "confirm":
          return "gate";
        case "approve":
          return "holder approval";
        case "intent":
          return "holder intent";
        case "quote":
          return "desk";
        default: {
          const unreachable: never = line.subject.step;
          return unreachable;
        }
      }
    default: {
      const unreachable: never = line;
      return unreachable;
    }
  }
}

/** "SANDBOX 1 · SIMULATED 2", or a plain statement when no verified payment names a rail. */
export function railsText(p: Posture): string {
  if (p.rails.length === 0) return "no verified payments in this window";
  return p.rails.map((r) => `${r.rail.toUpperCase()} ${r.count}`).join(" · ");
}

/** Nearest-rank percentile of an ascending list; null when it is empty. */
export function nearestRank(sorted: readonly number[], q: number): number | null {
  if (sorted.length === 0) return null;
  const index = Math.max(0, Math.ceil((q * sorted.length) / 100) - 1);
  return sorted[Math.min(index, sorted.length - 1)] ?? null;
}

/** "<part> of <whole> · <share>%", one decimal, truncated. */
export function formatShare(part: number, whole: number): string {
  if (whole === 0) return "none in this window";
  return `${part} of ${whole} · ${(Math.floor((part * 1000) / whole) / 10).toFixed(1)}%`;
}

/** Cents as a decimal amount with two digits. */
export function formatCents(cents: number): string {
  const abs = Math.abs(cents);
  const text = `${Math.trunc(abs / 100)}.${String(abs % 100).padStart(2, "0")}`;
  return cents < 0 ? `-${text}` : text;
}

/** An attack that moved money is a breach even when the line says it was blocked. */
function outcomeOf(line: ConsoleLine): Outcome {
  if (line.source === "attack" && line.subject.moved_cents !== 0) return "breach";
  return cueFor(line).outcome;
}

function consentOf(line: ConsoleLine): { certified: boolean; withConsent: boolean } {
  if (line.event?.verdict !== "MET" || !line.forensic) return { certified: false, withConsent: false };
  const category = (line.forensic.cava as Record<string, unknown>).category as unknown;
  return { certified: category === "payments", withConsent: line.forensic.consent !== null };
}

interface Bucket {
  count: number;
  seqs: number[];
}

const bucket = (): Bucket => ({ count: 0, seqs: [] });
/** A count with its noun, singular when there is one. */
export function counted(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

const push = (b: Bucket, seq: number): void => {
  b.count += 1;
  b.seqs.push(seq);
};
const addUnique = (list: string[], item: string): void => {
  if (!list.includes(item)) list.push(item);
};

interface AttackAcc {
  kind: string;
  attempts: number;
  blocked: number;
  breaches: number;
  movedCents: number;
  stoppedAt: string[];
  seqs: number[];
}

interface LayerAcc {
  layer: string;
  denials: number;
  kinds: string[];
  seqs: number[];
}

/** Posture metrics over a window of lines, each with the seqs it counted. */
export function computePosture(lines: readonly ConsoleLine[]): Posture {
  const decided = bucket();
  const verified = bucket();
  const denied = bucket();
  const breaches = bucket();
  const stepsRan = bucket();
  const certified = bucket();
  const withConsent = bucket();
  const attributed = bucket();
  const providers = new Map<string, number>();
  const rails = new Map<string, number[]>();
  const latencies: { us: number; seq: number }[] = [];
  const attacks = new Map<string, AttackAcc>(
    ATTACK_KINDS.map((kind) => [kind, { kind, attempts: 0, blocked: 0, breaches: 0, movedCents: 0, stoppedAt: [], seqs: [] }]),
  );
  const layers = new Map<string, LayerAcc>(LAYERS.map((layer) => [layer, { layer, denials: 0, kinds: [], seqs: [] }]));
  let movedCents = 0;

  for (const line of lines) {
    const outcome = outcomeOf(line);
    const layer = layerOf(line);
    const isDecision = outcome === "pass" || outcome === "deny" || outcome === "breach";

    if (isDecision) {
      push(decided, line.seq);
      if (line.meta !== null) {
        push(attributed, line.seq);
        providers.set(line.meta.provider, (providers.get(line.meta.provider) ?? 0) + 1);
      }
    }
    if (outcome === "pass") {
      push(verified, line.seq);
      const rail = railOf(line);
      if (rail !== null) rails.set(rail, [...(rails.get(rail) ?? []), line.seq]);
    }
    if (outcome === "deny") push(denied, line.seq);
    if (outcome === "breach") push(line.source === "attack" ? breaches : stepsRan, line.seq);

    if (line.event) latencies.push({ us: line.event.lat_us, seq: line.seq });

    const consent = consentOf(line);
    if (consent.certified) push(certified, line.seq);
    if (consent.certified && consent.withConsent) push(withConsent, line.seq);

    let attackKind: string | null = null;
    if (line.source === "attack") {
      attackKind = line.subject.attack;
      movedCents += Math.abs(line.subject.moved_cents);
      let row = attacks.get(attackKind);
      if (!row) {
        row = { kind: attackKind, attempts: 0, blocked: 0, breaches: 0, movedCents: 0, stoppedAt: [], seqs: [] };
        attacks.set(attackKind, row);
      }
      row.attempts += 1;
      row.seqs.push(line.seq);
      row.movedCents += Math.abs(line.subject.moved_cents);
      if (outcome === "breach") {
        row.breaches += 1;
      } else {
        row.blocked += 1;
        addUnique(row.stoppedAt, layer);
      }
    }

    if (outcome === "deny") {
      let row = layers.get(layer);
      if (!row) {
        row = { layer, denials: 0, kinds: [], seqs: [] };
        layers.set(layer, row);
      }
      row.denials += 1;
      row.seqs.push(line.seq);
      if (attackKind !== null) addUnique(row.kinds, attackKind);
    }
  }

  const sorted = latencies.map((l) => l.us).sort((a, b) => a - b);
  return {
    window: { first: lines[0]?.seq ?? null, last: lines[lines.length - 1]?.seq ?? null, lines: lines.length },
    decided,
    verified,
    denied,
    breaches,
    stepsRan,
    movedCents,
    attacks: [...attacks.values()],
    layers: [...layers.values()],
    consent: { certified, withConsent },
    latency: {
      samples: sorted.length,
      p50Us: nearestRank(sorted, 50),
      p95Us: nearestRank(sorted, 95),
      seqs: latencies.map((l) => l.seq),
    },
    attribution: {
      attributed,
      byProvider: [...providers.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([provider, count]) => ({ provider, count })),
    },
    rails: [...rails.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([rail, seqs]) => ({ rail, count: seqs.length, seqs })),
  };
}
