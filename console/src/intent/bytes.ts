import * as b64 from "../explorer/bytes";

/** The four fields a holder signs: what to pay, to whom, for which invoice. */
export interface IntentFields {
  amount_cents: number;
  currency: string;
  recipient: string;
  reference: string;
}

/** The simulated bank's signed funds statement, as the desk returns it. */
export interface BankState {
  subject: string;
  statement: string;
  balance_cents: number;
  currency: string;
  nonce: string;
  issued_at: number;
  expires_at: number;
  signature: string;
}

// Python's json.dumps escapes non-ASCII and control characters, so only text
// both sides write the same way is accepted: printable ASCII without spaces.
const PRINTABLE = /^[\x21-\x7e]+$/;

const text = (value: unknown): boolean => typeof value === "string" && PRINTABLE.test(value);
const count = (value: unknown, min: number): boolean =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= min;

function encode(prefix: string, payload: Record<string, string | number>): Uint8Array<ArrayBuffer> {
  const sorted = Object.keys(payload)
    .sort()
    .map((key) => [key, payload[key]]);
  return new TextEncoder().encode(`${prefix}${JSON.stringify(Object.fromEntries(sorted))}`);
}

/** The `intent/v1` bytes the holder signs; twin of the desk's `intent_bytes`. */
export function intentBytes(f: IntentFields): Uint8Array<ArrayBuffer> {
  if (!count(f.amount_cents, 1) || ![f.currency, f.recipient, f.reference].every(text)) {
    throw new Error("intent: malformed");
  }
  const { amount_cents, currency, recipient, reference } = f;
  return encode("intent/v1:", { amount_cents, currency, recipient, reference });
}

/** The `coop/v1` bytes the bank signed; twin of `SignedState.signable_bytes`. */
export function stateBytes(s: BankState): Uint8Array<ArrayBuffer> {
  const strings = [s.subject, s.statement, s.currency, s.nonce];
  const numbers = [s.balance_cents, s.issued_at, s.expires_at];
  if (!strings.every(text) || !numbers.every((n) => count(n, 0))) {
    throw new Error("state: malformed");
  }
  const { subject, statement, balance_cents, currency, nonce, issued_at, expires_at } = s;
  return encode("coop/v1:", { subject, statement, balance_cents, currency, nonce, issued_at, expires_at });
}

/** Integer cents as `200.00 USD`. */
export function formatAmount(cents: number, currency: string): string {
  const units = Math.floor(cents / 100);
  return `${units}.${String(cents % 100).padStart(2, "0")} ${currency}`;
}

/** Standard padded base64. */
export function toBase64(bytes: ArrayBuffer | Uint8Array): string {
  return b64.toBase64(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}

/** Standard padded base64 to bytes; anything non-canonical is refused. */
export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  return b64.fromBase64(text);
}

const BAD_SIGNATURE = "bad-signature: state signature invalid";

/**
 * Checks the bank's statement on this device, in the bank verifier's order:
 * signature, binding to this intent, then freshness.
 */
export async function verifyState(state: BankState, bankKey: string, intentHash: string, nowS: number): Promise<string> {
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = stateBytes(state);
  } catch {
    return "state: malformed";
  }
  try {
    const key = await crypto.subtle.importKey("raw", fromBase64(bankKey), { name: "Ed25519" }, false, ["verify"]);
    const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, fromBase64(state.signature), bytes);
    if (!valid) return BAD_SIGNATURE;
  } catch {
    return BAD_SIGNATURE;
  }
  if (state.nonce !== intentHash) return "state: not bound to this intent";
  if (nowS > state.expires_at) return "stale: state expired";
  if (nowS < state.issued_at) return "premature: state issued in future";
  return "ok: cooperative";
}
