import { WireError } from "../wire/parse";
import type { ConsoleLine } from "../wire/types";

export interface RuleView {
  readonly rule_id: string;
  readonly actor: string;
  readonly operation: string;
  readonly target: string;
  readonly amount_exact: boolean;
  readonly amount_lte_cents: number | null;
  readonly approval_required: boolean;
  readonly consent_required: boolean;
}

export interface PolicyView {
  readonly policy_id: string;
  readonly version: number;
  readonly rules: readonly RuleView[];
}

export interface ServerProvenance {
  readonly epoch: string;
  readonly window: { readonly first_seq: number; readonly last_seq: number; readonly retained: number };
  readonly registry: { readonly root: string; readonly leaves: number };
  readonly policies: readonly PolicyView[];
}

export interface Provenance {
  readonly source: "live" | "replay";
  readonly replay: string | null;
  readonly epoch: string | null;
  readonly window: { readonly first: number | null; readonly last: number | null; readonly lines: number };
  readonly evicted: boolean;
  readonly registry: { readonly root: string; readonly leaves: number; readonly from: string } | null;
  readonly policies: readonly PolicyView[] | null;
}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const exact = (v: unknown, keys: readonly string[]): v is Obj =>
  isObj(v) && Object.keys(v).length === keys.length && keys.every((k) => k in v);
const count = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const text = (v: unknown): v is string => typeof v === "string";
const flag = (v: unknown): v is boolean => typeof v === "boolean";

const RULE_KEYS = [
  "rule_id", "actor", "operation", "target", "amount_exact",
  "amount_lte_cents", "approval_required", "consent_required",
] as const;

function validRule(v: unknown): boolean {
  return (
    exact(v, RULE_KEYS) &&
    text(v["rule_id"]) && text(v["actor"]) && text(v["operation"]) && text(v["target"]) &&
    flag(v["amount_exact"]) && flag(v["approval_required"]) && flag(v["consent_required"]) &&
    (v["amount_lte_cents"] === null || Number.isSafeInteger(v["amount_lte_cents"]))
  );
}

function validPolicy(v: unknown): boolean {
  return (
    exact(v, ["policy_id", "version", "rules"]) &&
    text(v["policy_id"]) && count(v["version"]) &&
    Array.isArray(v["rules"]) && v["rules"].every(validRule)
  );
}

function valid(v: unknown): v is ServerProvenance {
  if (!exact(v, ["epoch", "window", "registry", "policies"])) return false;
  const { window, registry, policies } = v;
  return (
    text(v["epoch"]) &&
    exact(window, ["first_seq", "last_seq", "retained"]) &&
    count(window["first_seq"]) && count(window["last_seq"]) && count(window["retained"]) &&
    exact(registry, ["root", "leaves"]) &&
    text(registry["root"]) && /^[0-9a-f]{64}$/.test(registry["root"]) && count(registry["leaves"]) &&
    Array.isArray(policies) && policies.every(validPolicy)
  );
}

/** Parses the `GET /api/provenance` body; any deviation from the served shape throws `WireError`. */
export function parseProvenance(body: string): ServerProvenance {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new WireError("wire: malformed provenance");
  }
  if (!valid(parsed)) throw new WireError("wire: malformed provenance");
  return parsed;
}

/** What a window rests on: epoch, bounds, registry root and policies, each with where it came from. */
export function provenanceOf(
  lines: readonly ConsoleLine[],
  liveServer: ServerProvenance | null,
  replay: string | null,
): Provenance {
  // A live server describes a different run than a replayed window.
  const server = replay === null ? liveServer : null;
  const first = lines.length > 0 ? lines[0]!.seq : null;
  const last = lines.length > 0 ? lines[lines.length - 1]!.seq : null;
  let registry: Provenance["registry"] = null;
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i]!;
    const proof = line.forensic?.registry;
    if (proof) {
      registry = { root: proof.root, leaves: proof.leaves, from: `line #${line.seq}` };
      break;
    }
  }
  // The server's read may predate the newest proof; the registry only grows, so the larger one is newer.
  if (server !== null && (registry === null || server.registry.leaves >= registry.leaves)) {
    registry = { root: server.registry.root, leaves: server.registry.leaves, from: "server" };
  }
  return {
    source: replay === null ? "live" : "replay",
    replay,
    epoch: server?.epoch ?? null,
    window: { first, last, lines: lines.length },
    evicted: first !== null && first > 1,
    registry,
    policies: server?.policies ?? null,
  };
}
