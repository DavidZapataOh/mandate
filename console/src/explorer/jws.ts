import { ascii, fromJwsSegment, verifyEd25519, type Bytes } from "./bytes";

/** A compact JWS whose EdDSA signature verified, or why PyJWT would refuse it. */
export type JwsRead = { header: Record<string, unknown>; payload: Record<string, unknown> } | "malformed" | "bad-signature";

const utf8 = new TextDecoder("utf-8", { fatal: true });

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonObject(bytes: Bytes): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(utf8.decode(bytes));
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

// Python truthiness of a JSON value.
function truthy(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (isObject(value)) return Object.keys(value).length > 0;
  return value !== null && value !== false && value !== 0 && value !== "";
}

// Python int() of a JSON value, or null where it raises.
function pyInt(value: unknown): number | null {
  if (typeof value === "boolean") return Number(value);
  if (typeof value === "number") return Math.trunc(value);
  if (typeof value === "string" && /^\s*[+-]?\d+(?:_\d+)*\s*$/.test(value)) return Number(value.replaceAll("_", "").trim());
  return null;
}

function headerRefused(header: Record<string, unknown>): boolean {
  if (header.b64 === false) return true;
  if (Object.hasOwn(header, "kid") && typeof header.kid !== "string") return true;
  if (Object.hasOwn(header, "crit")) {
    const crit = header.crit;
    if (!Array.isArray(crit) || crit.length === 0) return true;
    if (!crit.every((ext) => ext === "b64" && Object.hasOwn(header, ext))) return true;
  }
  return header.alg !== "EdDSA";
}

function claimsRefused(payload: Record<string, unknown>, audience: boolean): boolean {
  if (Object.hasOwn(payload, "nbf")) {
    const nbf = pyInt(payload.nbf);
    if (nbf === null || nbf > Date.now() / 1000) return true;
  }
  if (audience && Object.hasOwn(payload, "aud") && truthy(payload.aud)) return true;
  if (Object.hasOwn(payload, "sub") && typeof payload.sub !== "string") return true;
  return Object.hasOwn(payload, "jti") && typeof payload.jti !== "string";
}

/**
 * PyJWT `jwt.decode(token, key, algorithms=["EdDSA"])` with exp and iat unchecked; `audience` false also skips the
 * audience check. The key must already be 32 bytes.
 */
export async function readJws(token: string, key: Bytes, audience: boolean): Promise<JwsRead> {
  const segments = token.split(".");
  if (segments.length !== 3) return "malformed";
  const [h, p, s] = segments as [string, string, string];
  let header: Record<string, unknown> | null, body: Bytes, signature: Bytes;
  try {
    header = jsonObject(fromJwsSegment(h));
    if (header === null) return "malformed";
    body = fromJwsSegment(p);
    signature = fromJwsSegment(s);
  } catch {
    return "malformed";
  }
  if (headerRefused(header)) return "malformed";
  if (!(await verifyEd25519(key, signature, ascii(`${h}.${p}`)))) return "bad-signature";
  const payload = jsonObject(body);
  if (payload === null || claimsRefused(payload, audience)) return "malformed";
  return { header, payload };
}
