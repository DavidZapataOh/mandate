// Test data only, built from the golden wire lines; the bundle gate fails the build if it ships.
import { ATTACK, CONFIRM, HOSTILE, patch } from "../../wire/__fixtures__/lines";
import { parseLine } from "../../wire/parse";
import type { Attribution, ConsoleLine, DecisionEvent } from "../../wire/types";

const CONFIRM_EVENT: DecisionEvent = JSON.parse(CONFIRM).event;
const ATTACK_JSON = JSON.parse(ATTACK);

export const SUMMARY = "MANDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) from checking-881";
export const NARRATIVE = "MANDATE_FIXTURE Swap the payee of the approved 200.00 USD bill to evil-666.";
export const SPARK_META: Attribution = { ...JSON.parse(HOSTILE).meta, provider: "meta-model-api", model: "muse-spark-1.3" };

/** The golden confirm event with another verdict, reason or latency. */
export function gateEvent(verdict: string, reason: string, lat_us = 61.0): DecisionEvent {
  return { ...CONFIRM_EVENT, verdict, reason, lat_us };
}

/** The golden confirmed payment (no attribution, gate latency 61 µs). */
export const confirmed = (): ConsoleLine => parseLine(CONFIRM);

/** The golden desk line at another step and status; no gate event unless given. */
export function desk(step: string, status: string, top: Record<string, unknown> = {}, subject: Record<string, unknown> = {}): ConsoleLine {
  return parseLine(patch(CONFIRM, { event: null, forensic: null, ...top }, { step, status, payment_id: null, reason: null, ...subject }));
}

/** The golden attack as another kind and layer; `gate` keeps its gate event and forensic block. */
export function attack(kind: string, layer: string, opts: { blocked?: boolean; gate?: DecisionEvent; origin?: "template" | "model"; seq?: number } = {}): ConsoleLine {
  const blocked = opts.blocked ?? true;
  return parseLine(
    patch(
      ATTACK,
      { seq: opts.seq ?? 4, event: opts.gate ?? null, forensic: opts.gate === undefined ? null : ATTACK_JSON.forensic },
      { attack: kind, layer, blocked, moved_cents: blocked ? 0 : 20000, origin: opts.origin ?? "template" },
    ),
  );
}

/** A Muse Code tool call decided by the gate. */
export function hook(verdict: string, reason: string): ConsoleLine {
  return parseLine(
    patch(ATTACK, {
      source: "hook",
      forensic: null,
      event: gateEvent(verdict, reason, 18.9),
      subject: { agent: "child-1", tool: "edit_file", targets: ["src/app.py"], tool_use_id: "MANDATE_FIXTURE-1" },
    }),
  );
}

/** A Muse Spark bill run: paid, denied, or only read (no gate event). */
export function bill(event: DecisionEvent | null, report_error: string | null = null): ConsoleLine {
  return parseLine(
    patch(CONFIRM, {
      source: "bill",
      event,
      forensic: null,
      meta: SPARK_META,
      subject: { proposal_call_id: "call_1", summary: SUMMARY, confirmation: null, report_error },
    }),
  );
}
