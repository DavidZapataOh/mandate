import { formatLatency } from "../shared/format";
import {
  type AttackRow, counted, DEFINITIONS, formatCents, formatShare, LABELS,
  type MetricKey, type Posture,
} from "./posture";
import type { Provenance } from "./provenance";
import { APPLICABILITY, CONTROLS, DISCLAIMER, evidenceText, type Control } from "./standards";

export interface ReportControl extends Omit<Control, "evidence"> {
  readonly evidence: string;
}

export interface Report {
  readonly report: "mandate-posture/1";
  readonly generatedAt: string;
  readonly disclaimer: string;
  readonly applicability: string;
  readonly provenance: Provenance;
  readonly metrics: Posture;
  readonly definitions: Readonly<Record<MetricKey, string>>;
  readonly controls: readonly ReportControl[];
}

export const TILES = ["decided", "verified", "denied", "breaches", "moved", "consent", "latency", "attribution"] as const;

/** Builds the report for a window; every field is derived from the posture and provenance given. */
export function buildReport(posture: Posture, provenance: Provenance, generatedAtMs: number): Report {
  return {
    report: "mandate-posture/1",
    generatedAt: new Date(generatedAtMs).toISOString(),
    disclaimer: DISCLAIMER,
    applicability: APPLICABILITY,
    provenance: orderedProvenance(provenance),
    metrics: posture,
    definitions: DEFINITIONS,
    controls: CONTROLS.map((c) => ({
      framework: c.framework, id: c.id, title: c.title, source: c.source, mandate: c.mandate,
      evidence: evidenceText(c.evidence, posture, provenance), gap: c.gap,
    })),
  };
}

// Server key order is not guaranteed; the export fixes it.
function orderedProvenance(p: Provenance): Provenance {
  return {
    source: p.source,
    replay: p.replay,
    epoch: p.epoch,
    window: { first: p.window.first, last: p.window.last, lines: p.window.lines },
    evicted: p.evicted,
    registry: p.registry && { root: p.registry.root, leaves: p.registry.leaves, from: p.registry.from },
    policies:
      p.policies &&
      p.policies.map((x) => ({
        policy_id: x.policy_id,
        version: x.version,
        rules: x.rules.map((r) => ({
          rule_id: r.rule_id, actor: r.actor, operation: r.operation, target: r.target,
          amount_exact: r.amount_exact, amount_lte_cents: r.amount_lte_cents,
          approval_required: r.approval_required, consent_required: r.consent_required,
        })),
      })),
  };
}

/** The display value of one posture tile. */
export function metricValue(key: (typeof TILES)[number], p: Posture): string {
  switch (key) {
    case "decided": return String(p.decided.count);
    case "verified": return String(p.verified.count);
    case "denied": return String(p.denied.count);
    case "breaches": return String(p.breaches.count);
    case "moved": return formatCents(p.movedCents);
    case "consent": return formatShare(p.consent.withConsent.count, p.consent.certified.count);
    case "attribution": return formatShare(p.attribution.attributed.count, p.decided.count);
    case "latency":
      if (p.latency.p50Us === null || p.latency.p95Us === null) return "no gate events in this window";
      return `p50 ${formatLatency(p.latency.p50Us)} · p95 ${formatLatency(p.latency.p95Us)} (${counted(p.latency.samples, "sample", "samples")})`;
  }
}

const ESCAPES: Readonly<Record<string, string>> = {
  "\\": "\\\\", "|": "\\|", "<": "&lt;", ">": "&gt;", "&": "&amp;", "[": "\\[", "]": "\\]", "`": "\\`",
};

/** Escapes text for a Markdown table cell so it stays one inert cell: no breakout, link, image, tag or autolink. */
export function cell(text: string): string {
  return text
    .replace(/\r\n|\r|\n/g, " ")
    .replace(/[\\|<>&[\]`]/g, (c) => ESCAPES[c]!)
    .replace(/:\/\//g, ":&#47;&#47;");
}

/** The report as JSON with a fixed key order and a trailing newline. */
export function reportJson(r: Report): string {
  return `${JSON.stringify(r, null, 2)}\n`;
}

const row = (cells: readonly string[]): string => `| ${cells.join(" | ")} |`;
const table = (head: readonly string[], rows: readonly (readonly string[])[]): string[] => [
  row(head),
  `|${head.map(() => "---").join("|")}|`,
  ...rows.map(row),
  "",
];

function registryEntries(r: NonNullable<Provenance["registry"]>): string {
  return r.leaves === 0 ? `0, registry empty (${cell(r.from)})` : `${r.leaves} (${cell(r.from)})`;
}

function sourceText(p: Provenance): string {
  if (p.source === "replay") return `replay ${cell(p.replay ?? "")} (recorded stream)`;
  return p.epoch === null ? "live console (server provenance unavailable)" : `live console (server epoch ${cell(p.epoch)})`;
}

/** A count of lines, singular when there is one. */
export function lineCount(n: number): string {
  return counted(n, "line", "lines");
}

/** Said of an attack kind that was attempted and at least once not blocked. */
export const NOT_STOPPED = "not stopped";

/** Where attempts of one kind were stopped, with "not stopped" when any got through. */
export function stoppedAtParts(a: AttackRow): readonly string[] {
  if (a.attempts === 0) return ["not attempted"];
  return a.breaches > 0 ? [...a.stoppedAt, NOT_STOPPED] : a.stoppedAt;
}

function windowText(p: Provenance): string {
  const { first, last, lines } = p.window;
  if (first === null || last === null) return "no lines";
  const base = `lines #${first} to #${last} (${lineCount(lines)})`;
  return p.evicted ? `${base}; lines before #${first} are outside this window` : base;
}

/** The report as Markdown; every cell derived from lines or the server is escaped. */
export function reportMarkdown(r: Report): string {
  const p = r.provenance;
  const m = r.metrics;
  const out: string[] = ["# Mandate posture report", "", cell(r.disclaimer), ""];
  out.push("## Provenance", "");
  out.push(...table(["Field", "Value"], [
    ["Generated", cell(r.generatedAt)],
    ["Source", sourceText(p)],
    ["Window", windowText(p)],
    ["Registry root", p.registry ? cell(p.registry.root) : "none in this window"],
    ["Registry entries", p.registry ? registryEntries(p.registry) : "none in this window"],
    ["Policies served", p.policies ? cell(p.policies.map((x) => `${x.policy_id} v${x.version}`).join(", ")) : "not served"],
  ]));
  out.push("## Posture", "");
  out.push(...table(["Metric", "Value", "Definition"], TILES.map((k) => [cell(LABELS[k]), cell(metricValue(k, m)), cell(r.definitions[k])])));
  out.push("## Attacks by kind", "", cell(r.definitions.attacks), "");
  out.push(...table(["Attack", "Attempts", "Blocked", "Not blocked", "Moved", "Stopped at"], m.attacks.map((a) => [
    cell(a.kind), String(a.attempts), String(a.blocked), String(a.breaches), formatCents(a.movedCents),
    cell(stoppedAtParts(a).join(", ")),
  ])));
  out.push("## Denials by layer", "", cell(r.definitions.layers), "");
  out.push(...table(["Layer", "Denials", "Attack kinds"], m.layers.map((l) => [
    cell(l.layer), String(l.denials), l.kinds.length === 0 ? "none" : cell(l.kinds.join(", ")),
  ])));
  out.push("## Framework mapping", "", cell(r.applicability), "");
  out.push(...table(
    ["Framework", "Provision", "Maps to (Mandate control)", "Evidence in this window", "Gap", "Source"],
    r.controls.map((c) => [
      cell(c.framework), cell(`${c.id}: ${c.title}`), cell(c.mandate), cell(c.evidence), cell(c.gap),
      // A fixed citation, not wire text: left as plain text.
      c.source,
    ]),
  ));
  return `${out.slice(0, -1).join("\n")}\n`;
}

/** Download name for the window the report covers. */
export function reportFileName(r: Report, ext: "md" | "json"): string {
  const { first, last } = r.provenance.window;
  return first === null || last === null ? `mandate-posture-empty.${ext}` : `mandate-posture-${first}-${last}.${ext}`;
}
