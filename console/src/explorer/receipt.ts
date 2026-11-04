/** Any JSON value. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** The canonical action (gate/cava.py). */
export interface Cava {
  version: string;
  runtime: string;
  executable: string;
  operation: string;
  category: string;
  targets: string[];
  reversible: boolean;
  freshness: { nonce: string; timestamp: number };
  evidence_refs: string[];
}

/** The holder's consent: the seven signed fields, its signature and its keys (standard base64). */
export interface ReceiptConsent {
  amount_cents: number;
  currency: string;
  recipient: string;
  reference: string;
  source: string;
  nonce: string;
  expires_at: number;
  signature: string;
  consent_key: string;
  holder_key: string;
  key_signature: string;
}

/** One registry log entry. */
export interface Entry {
  seq: number;
  kind: string;
  body: string;
}

/** Merkle inclusion proof of one entry (hex digests). */
export interface Proof {
  seq: number;
  leaves: number;
  leaf: string;
  siblings: string[];
  root: string;
}

/** Gate-signed registry seal (signature in standard base64). */
export interface Seal {
  v: number;
  anchor_id: string;
  seq_from: number;
  seq_to: number;
  root: string;
  ts: number;
  signature: string;
}

/** Identity of one model response and its encrypted reasoning. */
export interface ReasoningAnchor {
  blobs: string[];
  model: string;
  response_id: string;
  v: number;
}

/** The policy a decision was made under. */
export interface ReceiptPolicy {
  policy_id: string;
  policy_version: number;
  rule_id: string;
}

/** Proof receipt v2, field for field in wire order. */
export interface Receipt {
  v: 2;
  payment_id: string;
  certificate: string;
  sd: string;
  policy: ReceiptPolicy;
  registry: { entry: Entry; proof: Proof; seal: Seal };
  reasoning: ReasoningAnchor | null;
}

/** The gate-signed SD-JWT payload with every received Disclosure in place. */
export interface Disclosed {
  iss: string;
  iat: number;
  sub: string;
  cert_jti: string;
  cava: Omit<Cava, "targets"> & { targets?: string[]; action_salt?: string };
  consent: Pick<ReceiptConsent, "nonce" | "expires_at" | "consent_key"> &
    Partial<
      Pick<
        ReceiptConsent,
        "amount_cents" | "currency" | "recipient" | "reference" | "source" | "signature" | "holder_key" | "key_signature"
      >
    >;
}

/** A receipt that does not have the exact v2 shape; the message names the first malformed path. */
export class ReceiptError extends Error {
  override name = "ReceiptError";
}

/**
 * What a value must be. In a shape, a key ending in `?` may be absent; every other key is required and no unknown
 * key passes.
 */
export type Kind =
  | "string"
  | "integer"
  | "boolean"
  | { readonly literal: number | string | boolean }
  | { readonly pattern: RegExp }
  | { readonly array: Kind }
  | { readonly nullable: Kind }
  | { readonly shape: Readonly<Record<string, Kind>> };

/** Extra top-level receipt keys, spread after this module's keys. */
export const RECEIPT_EXTENSIONS: Readonly<Record<string, Kind>> = {};
/** Extra always-visible claims of the gate-signed payload, spread after this module's keys. */
export const DISCLOSED_EXTENSIONS: Readonly<Record<string, Kind>> = {};

const strings: Kind = { array: "string" };

const RECEIPT_SHAPE: Kind = {
  shape: {
    v: { literal: 2 },
    payment_id: "string",
    certificate: "string",
    sd: "string",
    policy: { shape: { policy_id: "string", policy_version: "integer", rule_id: "string" } },
    registry: {
      shape: {
        entry: { shape: { seq: "integer", kind: "string", body: "string" } },
        proof: { shape: { seq: "integer", leaves: "integer", leaf: "string", siblings: strings, root: "string" } },
        seal: {
          shape: {
            v: "integer", anchor_id: "string", seq_from: "integer", seq_to: "integer", root: "string", ts: "integer",
            signature: "string",
          },
        },
      },
    },
    reasoning: { nullable: { shape: { v: "integer", model: "string", response_id: "string", blobs: strings } } },
    ...RECEIPT_EXTENSIONS,
  },
};

const DISCLOSED_SHAPE: Kind = {
  shape: {
    iss: "string",
    iat: "integer",
    sub: "string",
    cert_jti: "string",
    cava: {
      shape: {
        version: "string",
        runtime: "string",
        executable: "string",
        operation: "string",
        category: "string",
        "targets?": strings,
        reversible: "boolean",
        freshness: { shape: { nonce: "string", timestamp: "integer" } },
        evidence_refs: strings,
        "action_salt?": { pattern: /^[0-9a-f]{64}$/ },
      },
    },
    consent: {
      shape: {
        nonce: "string",
        expires_at: "integer",
        consent_key: { pattern: /^[A-Za-z0-9+/]{43}=$/ },
        "amount_cents?": "integer",
        "currency?": "string",
        "recipient?": "string",
        "reference?": "string",
        "source?": "string",
        "signature?": "string",
        "holder_key?": "string",
        "key_signature?": "string",
      },
    },
    ...DISCLOSED_EXTENSIONS,
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// A key such as `__proto__` must stay an own data property of the copy.
function put(obj: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

function refuse(path: readonly string[]): never {
  throw new ReceiptError(path.length === 0 ? "receipt: malformed" : `receipt: ${path.join(".")} malformed`);
}

// A fresh copy of `value` checked against `kind`, keys in the shape's order.
function read(value: unknown, kind: Kind, path: readonly string[]): unknown {
  if (kind === "string") return typeof value === "string" ? value : refuse(path);
  if (kind === "integer") return Number.isSafeInteger(value) ? value : refuse(path);
  if (kind === "boolean") return typeof value === "boolean" ? value : refuse(path);
  if ("literal" in kind) return value === kind.literal ? value : refuse(path);
  if ("pattern" in kind) return typeof value === "string" && kind.pattern.test(value) ? value : refuse(path);
  if ("array" in kind) return Array.isArray(value) ? value.map((v) => read(v, kind.array, path)) : refuse(path);
  if ("nullable" in kind) return value === null ? null : read(value, kind.nullable, path);
  if (!isRecord(value)) return refuse(path);
  const out: Record<string, unknown> = {};
  const known = new Set<string>();
  for (const [spec, inner] of Object.entries(kind.shape)) {
    const optional = spec.endsWith("?");
    const key = optional ? spec.slice(0, -1) : spec;
    known.add(key);
    if (!Object.hasOwn(value, key)) {
      if (optional) continue;
      refuse([...path, key]);
    }
    put(out, key, read(value[key], inner, [...path, key]));
  }
  if (Object.keys(value).some((key) => !known.has(key))) refuse(path);
  return out;
}

/** A fresh copy of a proof receipt v2 with the exact shape at every level; throws ReceiptError otherwise. */
export function parseReceipt(value: unknown): Receipt {
  return read(value, RECEIPT_SHAPE, []) as Receipt;
}

/** A fresh copy of the rebuilt SD-JWT payload with the exact shape at every level; throws ReceiptError otherwise. */
export function parseDisclosed(value: unknown): Disclosed {
  return read(value, DISCLOSED_SHAPE, ["sd"]) as Disclosed;
}
