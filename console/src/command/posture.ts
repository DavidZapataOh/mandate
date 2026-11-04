import { cueFor, type Outcome } from "../scene/cues";
import type { ConsoleLine } from "../wire/types";

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
export const LAYERS: readonly string[] = ["gate", "bank verifier", "broker", "MCP proxy", "holder approval", "desk"];

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
  readonly breaches: Count;
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
}

export type MetricKey =
  | "decided" | "verified" | "denied" | "breaches" | "moved" | "consent" | "latency" | "attribution" | "attacks" | "layers";

export const LABELS: Readonly<Record<MetricKey, string>> = {
  decided: "Actions decided",
  verified: "Verified",
  denied: "Denied before execution",
  breaches: "Attacks not blocked",
  moved: "Moved by attacks",
  consent: "Holder consent on certified payments",
  latency: "Gate decision time",
  attribution: "Decisions naming their model call",
  attacks: "Attacks by kind",
  layers: "Denials by layer",
};

export const DEFINITIONS: Readonly<Record<MetricKey, string>> = {
  decided:
    "Lines in this window whose outcome is verified, denied or not blocked. Quotes and approvals waiting for the holder, and bill reads that never reached the gate, are not decisions.",
  verified:
    "Desk payments the bank confirmed, Muse Code tool calls the gate allowed, bill payments whose gate verdict is MET, and pinned Nimbus releases the deploy target accepted.",
  denied:
    "Decisions refused before anything executed: denied or expired desk steps, Muse Code calls and bill payments the gate refused, attacks blocked at their layer with zero cents moved, Nimbus scenario steps refused at the MCP proxy or gate.",
  breaches:
    "Attacks whose layer did not return its expected denial or that moved money, and Nimbus scenario steps that should have been refused but ran. Each one is a failed defense and is never counted as verified.",
  moved:
    "Sum of moved_cents over every attack line: cents that left the debited account during the attack step, measured from the bank balance before and after it.",
  consent:
    "Of the payments the gate certified in this window (gate verdict MET on a payments action), the share whose forensic record carries the holder's signed consent, which the gate verified and consumed once.",
  latency:
    "Time the gate spent deciding (lat_us of the decision event, measured inside the gate) over every line with a gate event; nearest-rank p50 and p95. Excludes model, network and bank time.",
  attribution:
    "Of the decisions in this window, the share whose line names the model call behind it (provider, model, request or response id). Template attacks, pinned Nimbus scenario steps and desk steps carry no model call and count as unattributed.",
  attacks:
    "One row per attack kind; attack lines only (Nimbus scenario steps count in the posture and the layers, not here). Attempts: attack lines of that kind. Blocked: the layer returned its pinned denial and zero cents moved. Stopped at: the layer that refused it.",
  layers:
    "Where each denial happened: the layer that refused the action (gate, bank verifier, broker, MCP proxy, holder approval, desk).",
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
  if (line.source === "attack" && line.subject.moved_cents > 0) return "breach";
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
  const certified = bucket();
  const withConsent = bucket();
  const attributed = bucket();
  const providers = new Map<string, number>();
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
    if (outcome === "pass") push(verified, line.seq);
    if (outcome === "deny") push(denied, line.seq);
    if (outcome === "breach") push(breaches, line.seq);

    if (line.event) latencies.push({ us: line.event.lat_us, seq: line.seq });

    const consent = consentOf(line);
    if (consent.certified) push(certified, line.seq);
    if (consent.certified && consent.withConsent) push(withConsent, line.seq);

    let attackKind: string | null = null;
    if (line.source === "attack") {
      attackKind = line.subject.attack;
      movedCents += line.subject.moved_cents;
      let row = attacks.get(attackKind);
      if (!row) {
        row = { kind: attackKind, attempts: 0, blocked: 0, breaches: 0, movedCents: 0, stoppedAt: [], seqs: [] };
        attacks.set(attackKind, row);
      }
      row.attempts += 1;
      row.seqs.push(line.seq);
      row.movedCents += line.subject.moved_cents;
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
  };
}
