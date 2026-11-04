import type { ConsoleLine, DeskSubject } from "../wire/types";
import { readConsent, type ConsentFields } from "./consent";

export type Phase = "waiting" | "refused" | "expired" | "approved" | "paid" | "denied";

export interface Outcome {
  phase: Phase;
  reason: string | null;
  paymentId: string | null;
  gateConsent: ConsentFields | null;
}

interface DeskLine {
  subject: DeskSubject;
  consent: unknown;
}

function deskOf(line: ConsoleLine): DeskLine | null {
  switch (line.source) {
    case "desk":
      return { subject: line.subject, consent: line.forensic?.consent ?? null };
    case "attack":
    case "hook":
    case "bill":
    case "deploy":
    case "bank":
      return null;
    default: {
      const unreachable: never = line;
      return unreachable;
    }
  }
}

function phaseFor(step: DeskSubject["step"], status: string): Phase | null {
  if (step === "quote") return status === "quoted" ? "waiting" : null;
  if (step === "approve") {
    if (status === "approved") return "approved";
    if (status === "expired") return "expired";
    return status === "denied" ? "refused" : null;
  }
  if (status === "confirmed") return "paid";
  return status === "denied" ? "denied" : null;
}

function gateConsentOf(step: DeskSubject["step"], consent: unknown): ConsentFields | null {
  if (step !== "confirm" || consent === null) return null;
  try {
    return readConsent(consent);
  } catch {
    return null;
  }
}

/** Where a quote stands, decided by the last desk line that names it. */
export function outcomeFor(lines: readonly ConsoleLine[], quoteId: string): Outcome {
  let out: Outcome = { phase: "waiting", reason: null, paymentId: null, gateConsent: null };
  for (const line of lines) {
    const desk = deskOf(line);
    if (desk === null || desk.subject.quote_id !== quoteId) continue;
    const phase = phaseFor(desk.subject.step, desk.subject.status);
    if (phase === null) continue;
    out = {
      phase,
      reason: desk.subject.reason,
      paymentId: desk.subject.payment_id,
      gateConsent: gateConsentOf(desk.subject.step, desk.consent),
    };
  }
  return out;
}

/** The quote the panel follows: the newest one a desk line names, else the newest pending. */
export function focusQuote(
  lines: readonly ConsoleLine[],
  pendingIds: readonly string[],
): string | null {
  let best: { seq: number; id: string } | null = null;
  for (const line of lines) {
    const desk = deskOf(line);
    const id = desk?.subject.quote_id ?? null;
    if (id !== null && (best === null || line.seq > best.seq)) best = { seq: line.seq, id };
  }
  return best?.id ?? pendingIds[pendingIds.length - 1] ?? null;
}

/** The gate's expiry rule on the given clock. */
export function expiredAt(fields: ConsentFields, nowMs: number): boolean {
  return Math.floor(nowMs / 1000) > fields.expires_at;
}
