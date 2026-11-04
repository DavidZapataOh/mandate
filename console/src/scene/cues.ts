import { formatLatency } from "../shared/format";
import type { Attribution, ConsoleLine, DecisionEvent } from "../wire/types";

export type IntruderKind = "thief" | "ghost" | "brute" | "forger" | "switcher";
export type ActorKind = "spark" | "code" | "agent" | "holder" | IntruderKind;
export type SealInput = "verify" | "deny" | "wait";
export type Outcome = "pass" | "deny" | "hold" | "breach" | "note";
export type Route = "desk" | "door" | "none";

export interface Cue {
  seq: number;
  actor: ActorKind;
  route: Route;
  seal: SealInput | null;
  outcome: Outcome;
  tag: string;
  bubble: string;
  alert: string | null;
  bank: boolean;
}

export const BUBBLE_MAX = 120;

const LABELS: Record<string, string> = {
  mcp_exfil: "poisoned MCP tool",
  replay: "replayed certificate",
  scope_escalation: "scope escalation",
  payee_swap: "payee swapped",
  amount_inflate: "amount inflated",
  post_cert_mutation: "changed after approval",
  forged_approval: "forged approval",
};

const INTRUDERS: Record<string, IntruderKind> = {
  mcp_exfil: "thief",
  replay: "ghost",
  scope_escalation: "brute",
  payee_swap: "forger",
  amount_inflate: "forger",
  forged_approval: "forger",
  post_cert_mutation: "switcher",
};

const LAYERS: Record<string, string> = {
  mcp: "MCP proxy",
  bank: "bank verifier",
  delegation: "broker",
  "gate->bank": "bank verifier",
  "model->gate": "gate",
  "holder->gate": "gate",
};

const TAGS: Record<string, string> = { spark: "Muse Spark", code: "Muse Code", agent: "agent", holder: "holder" };

export function attackLabel(kind: string): string {
  return LABELS[kind] ?? kind.replaceAll("_", " ");
}

function clip(text: string): string {
  return text.length > BUBBLE_MAX ? `${text.slice(0, BUBBLE_MAX - 1)}…` : text;
}

function agentOf(meta: Attribution | null): ActorKind {
  if (meta?.provider === "meta-model-api" || meta?.provider === "meta-fallback") return "spark";
  return meta?.provider === "muse-code" ? "code" : "agent";
}

const lat = (event: DecisionEvent | null): string => (event ? ` · ${formatLatency(event.lat_us)}` : "");

export function cueFor(line: ConsoleLine): Cue {
  const base = { seq: line.seq, alert: null, bank: false };
  switch (line.source) {
    case "desk": {
      const s = line.subject;
      const agent = agentOf(line.meta);
      const walker = (actor: ActorKind) => ({ actor, tag: TAGS[actor] as string });
      if (s.status === "denied" || s.status === "expired") {
        const holder = s.step === "approve";
        return {
          ...base,
          ...walker(holder ? "holder" : agent),
          route: holder ? "none" : "desk",
          seal: "deny",
          outcome: "deny",
          bubble: clip(`${s.summary} · denied`),
          alert: `denied · ${s.reason ?? s.status}${lat(line.event)}`,
        };
      }
      if (s.status === "quoted") {
        return { ...base, ...walker(agent), route: "desk", seal: "wait", outcome: "hold", bubble: clip(`${s.summary} · waiting for the holder`) };
      }
      if (s.status === "approved") {
        return { ...base, ...walker("holder"), route: "none", seal: "wait", outcome: "hold", bubble: clip(`Holder approved: ${s.summary}`) };
      }
      if (s.status === "confirmed") {
        return { ...base, ...walker(agent), route: "desk", seal: "verify", outcome: "pass", bubble: clip(`${s.summary} · verified${lat(line.event)}`), bank: true };
      }
      return { ...base, ...walker(agent), route: "none", seal: null, outcome: "note", bubble: clip(`${s.step}: ${s.status}`) };
    }
    case "attack": {
      const s = line.subject;
      const actor = INTRUDERS[s.attack] ?? "thief";
      const tag = s.origin === "model" ? "open-weights attacker" : "template attack";
      const label = attackLabel(s.attack);
      const common = { ...base, actor, tag, route: "door" as const, bubble: clip(s.narrative) };
      if (!s.blocked) {
        return { ...common, seal: null, outcome: "breach", alert: `NOT BLOCKED · ${label} · ${(s.moved_cents / 100).toFixed(2)} moved` };
      }
      const where = line.event ? formatLatency(line.event.lat_us) : `at the ${LAYERS[s.layer] ?? s.layer}`;
      return { ...common, seal: "deny", outcome: "deny", alert: `denied · ${label} · ${where}` };
    }
    case "hook": {
      const s = line.subject;
      const what = [s.tool, ...s.targets].join(" ");
      const common = { ...base, actor: "code" as const, tag: TAGS.code as string, route: "none" as const };
      if (line.event?.verdict === "MET") {
        return { ...common, seal: null, outcome: "pass", bubble: clip(`${what} · allowed`) };
      }
      return {
        ...common,
        seal: "deny",
        outcome: "deny",
        bubble: clip(`${what} · denied`),
        alert: `denied · ${s.tool} · ${line.event?.reason ?? "no decision"}`,
      };
    }
    case "bill": {
      const s = line.subject;
      const common = { ...base, actor: "spark" as const, tag: TAGS.spark as string };
      if (!line.event) {
        const bubble = s.report_error ? `Bill report failed: ${s.report_error}` : `Read bill: ${s.summary}`;
        return { ...common, route: "none", seal: null, outcome: "note", bubble: clip(bubble) };
      }
      if (line.event.verdict === "MET") {
        return { ...common, route: "desk", seal: "verify", outcome: "pass", bubble: clip(`Bill paid: ${s.summary}${lat(line.event)}`), alert: null, bank: true };
      }
      return {
        ...common,
        route: "desk",
        seal: "deny",
        outcome: "deny",
        bubble: clip(`Bill denied: ${s.summary}`),
        alert: `denied · ${line.event.reason}${lat(line.event)}`,
        bank: false,
      };
    }
  }
}
