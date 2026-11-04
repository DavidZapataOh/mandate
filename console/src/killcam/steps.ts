import { cueFor } from "../scene/cues";
import type { ConsoleLine, DecisionEvent, Forensic } from "../wire/types";

export type StepId = "desk" | "broker" | "mcp" | "canonicalize" | "hash" | "policy" | "consent" | "certificate" | "bank" | "target";
export type StepStatus = "passed" | "failed" | "skipped" | "unreached";

export interface KillStep {
  readonly id: StepId;
  readonly title: string;
  readonly status: StepStatus;
  readonly detail: string;
  readonly evidence: string | null;
}

const TITLES: Record<StepId, string> = {
  desk: "Desk",
  broker: "Broker",
  mcp: "MCP proxy",
  canonicalize: "Canonicalize",
  hash: "Hash",
  policy: "Policy rule",
  consent: "Holder consent",
  certificate: "Certificate",
  bank: "Bank verifier",
  target: "Deploy target",
};

type Verifier = "bank" | "target";
type GateId = "canonicalize" | "hash" | "policy" | "consent" | "certificate";

const GATE: readonly GateId[] = ["canonicalize", "hash", "policy", "consent", "certificate"];

const step = (id: StepId, status: StepStatus, detail: string, evidence: string | null = null): KillStep => ({
  id,
  title: TITLES[id],
  status,
  detail,
  evidence,
});

const unreached = (id: StepId): KillStep => step(id, "unreached", "Not reached");

function subjectReason(line: ConsoleLine): string | null {
  switch (line.source) {
    case "attack":
    case "deploy":
      return line.subject.reason;
    case "desk":
      return line.subject.reason ?? line.subject.status;
    case "hook":
    case "bill":
      return null;
    default: {
      const never: never = line;
      return never;
    }
  }
}

function layerOf(line: ConsoleLine): string | null {
  switch (line.source) {
    case "attack":
    case "deploy":
      return line.subject.layer;
    case "desk":
    case "hook":
    case "bill":
      return null;
    default: {
      const never: never = line;
      return never;
    }
  }
}

const verifierOf = (line: ConsoleLine): Verifier => (line.source === "deploy" ? "target" : "bank");
const short = (hash: string): string => hash.slice(0, 12);

function ruleOf(forensic: Forensic | null, event: DecisionEvent | null): string {
  if (forensic?.policy.rule_id) return `rule ${forensic.policy.rule_id}`;
  return `policy ${forensic?.policy.policy_id ?? event?.policy ?? ""}`;
}

function canonicalize(forensic: Forensic | null): KillStep {
  if (!forensic) return step("canonicalize", "passed", "Canonical object not recorded in this line");
  const { cava } = forensic;
  const targets = Array.isArray(cava.targets) ? cava.targets.length : 0;
  return step("canonicalize", "passed", `${String(cava.executable)} ${String(cava.operation)} · ${targets} targets`, JSON.stringify(cava));
}

function consentStep(forensic: Forensic | null): KillStep {
  const consent = forensic?.consent;
  if (!consent) return step("consent", "skipped", "No consent presented");
  const amount = (Number(consent.amount_cents) / 100).toFixed(2);
  return step("consent", "passed", `signed for ${amount} ${String(consent.currency)} to ${String(consent.recipient)}`, JSON.stringify(consent));
}

function rest(from: readonly StepId[]): KillStep[] {
  return from.map(unreached);
}

/** The gate's own hash and canonical object, or null when the record disagrees with itself. */
function gateHead(event: DecisionEvent | null, forensic: Forensic | null): KillStep[] | null {
  if (forensic && event && forensic.action_hash !== event.action) return null;
  const hash = event?.action ?? forensic?.action_hash;
  if (!hash) return null;
  return [canonicalize(forensic), step("hash", "passed", hash)];
}

function refusedByGate(line: ConsoleLine, event: DecisionEvent, forensic: Forensic | null): KillStep[] | null {
  const head = gateHead(event, forensic);
  if (!head || forensic?.cert_claims) return null;
  const verifier = verifierOf(line);
  const rule = ruleOf(forensic, event);
  const evidence = `${rule} · ${event.verdict}`;
  if (layerOf(line) === "mcp") {
    return [
      ...head,
      step("mcp", "failed", event.reason, `${event.policy} · ${event.verdict}`),
      ...rest(["policy", "consent", "certificate", verifier]),
    ];
  }
  if (event.reason.startsWith("consent:")) {
    const consent = forensic?.consent ? JSON.stringify(forensic.consent) : null;
    return [
      ...head,
      step("policy", "passed", `${rule} satisfied`),
      step("consent", "failed", event.reason, consent),
      ...rest(["certificate", verifier]),
    ];
  }
  return [...head, step("policy", "failed", event.reason, evidence), ...rest(["consent", "certificate", verifier])];
}

function refusedPastGate(line: ConsoleLine, event: DecisionEvent, forensic: Forensic | null): KillStep[] | null {
  const reason = subjectReason(line);
  const head = gateHead(event, forensic);
  if (!reason || !event.cert || !head) return null;
  const certified = forensic?.cert_claims ?? null;
  if (certified && (certified.action_hash !== event.action || certified.verdict !== "MET")) return null;
  const claims = certified ? JSON.stringify(certified) : null;
  return [
    ...head,
    step("policy", "passed", `${ruleOf(forensic, event)} satisfied`),
    consentStep(forensic),
    step("certificate", "passed", `MET over ${short(event.action)}`, claims),
    step(verifierOf(line), "failed", reason),
  ];
}

function refusedByVerifier(line: ConsoleLine, forensic: Forensic): KillStep[] | null {
  const layer = layerOf(line);
  const claims = forensic.cert_claims;
  const reason = subjectReason(line);
  if (line.source !== "attack" || !claims || !reason) return null;
  if (layer !== "bank" && layer !== "gate->bank") return null;
  if (claims.action_hash !== forensic.action_hash || claims.verdict !== "MET" || claims.policy_id !== forensic.policy.policy_id) return null;
  return [
    canonicalize(forensic),
    step("hash", "passed", forensic.action_hash),
    step("policy", "passed", `${ruleOf(forensic, null)} satisfied`),
    consentStep(forensic),
    step("certificate", "passed", `MET over ${short(forensic.action_hash)} · revocation index ${String(claims.revocation_index)}`, JSON.stringify(claims)),
    step("bank", "failed", reason),
  ];
}

function refusedBeforeGate(line: ConsoleLine): KillStep[] | null {
  const reason = subjectReason(line);
  if (!reason) return null;
  const layer = layerOf(line);
  let first: StepId | null = null;
  if (line.source === "desk") first = "desk";
  else if (line.source === "attack" && layer === "delegation") first = "broker";
  else if (line.source === "attack" && layer === "mcp") first = "mcp";
  if (!first) return null;
  return [step(first, "failed", reason), ...rest([...GATE, verifierOf(line)])];
}

/** The verification steps a denied line's forensic record proves, or null when it proves none. */
export function killSteps(line: ConsoleLine): KillStep[] | null {
  if (cueFor(line).outcome !== "deny") return null;
  const { event, forensic } = line;
  if (event && event.verdict !== "MET") return refusedByGate(line, event, forensic);
  if (event) return refusedPastGate(line, event, forensic);
  if (forensic) return refusedByVerifier(line, forensic);
  return refusedBeforeGate(line);
}

/** The caption naming the step that refused, empty when none did. */
export function killedAt(steps: readonly KillStep[]): string {
  const failed = steps.find((s) => s.status === "failed");
  return failed ? `Killed at ${failed.title}: ${failed.detail}` : "";
}
