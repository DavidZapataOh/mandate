import { parseLine } from "../wire/parse";

/** What a pasted text turned out to be. */
export type Pasted =
  | { kind: "receipt"; value: unknown }
  | { kind: "certificate"; token: string }
  | { kind: "payment"; id: string }
  | { kind: "line"; seq: number; paymentId: string | null }
  | { kind: "unknown"; reason: string };

// A desk payment id, or the bank's transfer id when a sandbox rail paid it.
const PAYMENT = /^(?:pay:[0-9]{6,}|(?:sandbox_)?account_transfer_[A-Za-z0-9]{1,64})$/;
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const REFUSED = "Paste a receipt, a certificate, a payment id or a console line";

function json(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** The kind of a pasted text; anything unrecognised is refused with a reason. */
export function classify(text: string): Pasted {
  const trimmed = text.trim();
  if (PAYMENT.test(trimmed)) return { kind: "payment", id: trimmed };
  if (COMPACT_JWS.test(trimmed)) return { kind: "certificate", token: trimmed };
  const value = json(trimmed);
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { kind: "unknown", reason: REFUSED };
  const version = (value as Record<string, unknown>).v;
  if (version === 2) return { kind: "receipt", value };
  if (version !== 3) return { kind: "unknown", reason: REFUSED };
  try {
    const line = parseLine(trimmed);
    // Only a desk line names the payment its receipt is stored under.
    return { kind: "line", seq: line.seq, paymentId: line.source === "desk" ? line.subject.payment_id : null };
  } catch {
    return { kind: "unknown", reason: "This console line is malformed" };
  }
}
