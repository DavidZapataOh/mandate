import { ascii, sha256, toBase64Url, type Bytes } from "./bytes";
import { readJws } from "./jws";
import type { Json } from "./receipt";

/** JWT `typ` of a proof receipt's SD-JWT. */
export const RECEIPT_TYP = "mandate-receipt+sd-jwt";
const SD_ALG = "sha-256";

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const utf8 = new TextDecoder("utf-8", { fatal: true });

class Refused extends Error {}

// Python base64.urlsafe_b64decode after gate/sdjwt.py's re-padding: non-alphabet characters are skipped and a
// complete pad ends the input, as binascii.a2b_base64 does outside strict mode.
function pyUrlsafeDecode(text: string): Bytes | null {
  const padded = (text + "=".repeat((4 - (text.length % 4)) % 4)).replaceAll("-", "+").replaceAll("_", "/");
  const out: number[] = [];
  let quad = 0;
  let left = 0;
  let pads = 0;
  for (const ch of padded) {
    if (ch === "=") {
      if (quad >= 2 && quad + ++pads >= 4) return new Uint8Array(out);
      continue;
    }
    const v = B64.indexOf(ch);
    if (v < 0) continue;
    pads = 0;
    if (quad === 0) left = v;
    else if (quad === 1) {
      out.push(((left << 2) | (v >> 4)) & 0xff);
      left = v & 0x0f;
    } else if (quad === 2) {
      out.push(((left << 4) | (v >> 2)) & 0xff);
      left = v & 0x03;
    } else out.push(((left << 6) | v) & 0xff);
    quad = (quad + 1) % 4;
  }
  return quad === 0 ? new Uint8Array(out) : null;
}

function decodeJson(text: string): Json | undefined {
  const bytes = pyUrlsafeDecode(text);
  if (bytes === null) return undefined;
  try {
    return JSON.parse(utf8.decode(bytes)) as Json;
  } catch {
    return undefined;
  }
}

function isObject(value: Json): value is { [key: string]: Json } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// A disclosed name such as `__proto__` must stay an own data property.
function put(obj: { [key: string]: Json }, key: string, value: Json): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

/** Unpadded base64url SHA-256 over the ASCII Disclosure (RFC 9901 §4.2.3). */
export async function disclosureDigest(text: string): Promise<string> {
  return toBase64Url(await sha256(ascii(text)));
}

/** A Disclosure's claim name and value, or null unless it is a JSON array of three with string salt and name. */
export function readDisclosure(text: string): { name: string; value: Json } | null {
  const item = decodeJson(text);
  if (!Array.isArray(item) || item.length !== 3) return null;
  const [salt, name, value] = item as [Json, Json, Json];
  return typeof salt === "string" && typeof name === "string" ? { name, value } : null;
}

interface Walk {
  found: ReadonlyMap<string, string>;
  used: Set<string>;
  seen: Set<string>;
  disclosed: string[];
}

function walk(node: Json, w: Walk): Json {
  if (Array.isArray(node)) {
    if (node.some((v) => isObject(v) && Object.hasOwn(v, "..."))) throw new Refused("sd-jwt: array disclosures unsupported");
    return node.map((v) => walk(v, w));
  }
  if (!isObject(node)) return node;
  const out: { [key: string]: Json } = {};
  for (const [key, value] of Object.entries(node)) if (key !== "_sd") put(out, key, walk(value, w));
  const digests = Object.hasOwn(node, "_sd") ? node._sd : [];
  if (!Array.isArray(digests) || !digests.every((d) => typeof d === "string")) throw new Refused("sd-jwt: malformed");
  for (const d of digests as string[]) {
    if (w.seen.has(d)) throw new Refused("sd-jwt: digest repeated");
    w.seen.add(d);
    const text = w.found.get(d);
    if (text === undefined) continue;
    w.used.add(d);
    const item = decodeJson(text);
    if (!Array.isArray(item) || item.length !== 3) throw new Refused("sd-jwt: disclosure malformed");
    const [, name, value] = item as [Json, Json, Json];
    if (typeof name !== "string" || name === "_sd" || name === "..." || Object.hasOwn(out, name)) {
      throw new Refused("sd-jwt: claim name refused");
    }
    w.disclosed.push(name);
    put(out, name, walk(value, w));
  }
  return out;
}

/**
 * Verify a compact SD-JWT `<JWT>~<D.1>~...~<D.N>~` and rebuild its payload (RFC 9901 §7.1), with the checks and
 * reasons of gate/sdjwt.py `process` in its order; `disclosed` names the rebuilt claims in walk order.
 */
export async function processSdJwt(
  text: string,
  key: Bytes,
  typ: string,
): Promise<{ payload: Record<string, Json>; disclosed: string[] } | { reason: string }> {
  const parts = text.split("~");
  if (parts.length < 2 || parts.at(-1) !== "" || !/^[\x00-\x7f]*$/.test(text)) return { reason: "sd-jwt: malformed" };
  if (key.length !== 32) return { reason: "sd-jwt: malformed" };
  const read = await readJws(parts[0]!, key, true);
  if (read === "malformed") return { reason: "sd-jwt: malformed" };
  if (read === "bad-signature") return { reason: "sd-jwt: bad signature" };
  if (read.header.typ !== typ) return { reason: "sd-jwt: wrong type" };
  if (Object.hasOwn(read.payload, "_sd_alg") && read.payload._sd_alg !== SD_ALG) return { reason: "sd-jwt: unsupported digest" };
  const found = new Map<string, string>();
  for (const disclosure of parts.slice(1, -1)) {
    const hashed = await disclosureDigest(disclosure);
    if (found.has(hashed)) return { reason: "sd-jwt: disclosure repeated" };
    found.set(hashed, disclosure);
  }
  const w: Walk = { found, used: new Set(), seen: new Set(), disclosed: [] };
  let rebuilt: Json;
  try {
    rebuilt = walk(read.payload as Json, w);
  } catch (error) {
    if (error instanceof Refused) return { reason: error.message };
    throw error;
  }
  if (w.used.size !== found.size) return { reason: "sd-jwt: disclosure not referenced" };
  const payload = rebuilt as Record<string, Json>;
  delete payload._sd_alg;
  return { payload, disclosed: w.disclosed };
}
