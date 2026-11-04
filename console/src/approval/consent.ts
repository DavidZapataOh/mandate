export interface ConsentFields {
  amount_cents: number;
  currency: string;
  expires_at: number;
  nonce: string;
  recipient: string;
  reference: string;
  source: string;
}

/** The seven consent fields in the order their bytes are written. */
export const CONSENT_FIELDS = [
  "amount_cents",
  "currency",
  "expires_at",
  "nonce",
  "recipient",
  "reference",
  "source",
] as const;

export class ApprovalError extends Error {}

const PRINTABLE = /^[\x21-\x7e]+$/;

function malformed(): ApprovalError {
  return new ApprovalError("approval: malformed consent");
}

/** Validates a consent object and returns a fresh copy of its seven fields. */
export function readConsent(value: unknown): ConsentFields {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw malformed();
  }
  const raw = value as Record<string, unknown>;
  const keys = Object.keys(raw);
  if (
    keys.length !== CONSENT_FIELDS.length ||
    !CONSENT_FIELDS.every((name) => keys.includes(name))
  ) {
    throw malformed();
  }
  const text = (name: (typeof CONSENT_FIELDS)[number]): string => {
    const field = raw[name];
    if (typeof field !== "string" || !PRINTABLE.test(field)) throw malformed();
    return field;
  };
  const whole = (name: "amount_cents" | "expires_at", least: number): number => {
    const field = raw[name];
    if (typeof field !== "number" || !Number.isSafeInteger(field) || field < least) {
      throw malformed();
    }
    return field;
  };
  return {
    amount_cents: whole("amount_cents", 1),
    currency: text("currency"),
    expires_at: whole("expires_at", 0),
    nonce: text("nonce"),
    recipient: text("recipient"),
    reference: text("reference"),
    source: text("source"),
  };
}

/** The exact bytes the holder signs and the gate checks. */
export function consentBytes(fields: ConsentFields): Uint8Array {
  const ordered: Record<string, string | number> = {};
  for (const name of CONSENT_FIELDS) ordered[name] = fields[name];
  return new TextEncoder().encode(`consent/v1:${JSON.stringify(ordered)}`);
}

/** Hex sha256 of the consent bytes, or null when WebCrypto is unavailable. */
export async function consentHash(
  fields: ConsentFields,
  subtle: SubtleCrypto | null = globalThis.crypto?.subtle ?? null,
): Promise<string | null> {
  if (subtle === null) return null;
  const digest = await subtle.digest("SHA-256", consentBytes(fields) as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Lowercase hex in groups of eight, separated by one space. */
export function groupHex(hex: string): string {
  return (hex.match(/.{1,8}/g) ?? []).join(" ");
}

/** Cents as a decimal amount followed by its currency. */
export function formatAmount(cents: number, currency: string): string {
  const whole = Math.floor(cents / 100);
  return `${whole}.${String(cents % 100).padStart(2, "0")} ${currency}`;
}

/** Unix seconds as `YYYY-MM-DD HH:MM:SS UTC`. */
export function utcTime(epochS: number): string {
  return `${new Date(epochS * 1000).toISOString().slice(0, 19).replace("T", " ")} UTC`;
}
