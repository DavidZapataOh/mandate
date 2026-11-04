import { ascii, fromHex, sha256, toBase64, toHex, type Bytes } from "./bytes";

// Python's ensure_ascii escapes everything outside 0x20..0x7e; JSON.stringify already escaped the controls.
function str(s: string): string {
  return JSON.stringify(s).replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

// Python sorts keys by code point; JavaScript's `<` compares UTF-16 code units.
function byCodePoint(a: string, b: string): number {
  const x = [...a];
  const y = [...b];
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

/** Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True) of a JSON value. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean") return String(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("canon: unsupported number");
    return String(value);
  }
  if (typeof value === "string") return str(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    entries.sort(([a], [b]) => byCodePoint(a, b));
    return `{${entries.map(([k, v]) => `${str(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  throw new Error("canon: unsupported value");
}

/** Hex SHA-256 over ASCII text or raw bytes. */
export async function sha256Hex(text: string | Bytes): Promise<string> {
  return toHex(await sha256(typeof text === "string" ? ascii(text) : text));
}

/** Hex HMAC-SHA256 over ASCII text keyed by a 32-byte salt (gate/cava.py action_commitment). */
export async function hmacSha256Hex(keyHex: string, text: string): Promise<string> {
  const salt = fromHex(keyHex);
  if (salt.length !== 32) throw new Error("canon: salt must be 32 bytes");
  const key = await crypto.subtle.importKey("raw", salt, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, ascii(text))));
}

/** gate/consent.py key_bytes: what the paired key signs to certify a one-time consent key for one nonce. */
export function keyBytes(consentKey: Bytes, nonce: string): Bytes {
  if (consentKey.length !== 32 || typeof nonce !== "string" || !/^[\x21-\x7e]+$/.test(nonce)) {
    throw new Error("consent: malformed");
  }
  return ascii(`consent-key/v1:${canonicalJson({ consent_key: toBase64(consentKey), nonce })}`);
}
