/** Bytes Web Crypto accepts as a BufferSource. */
export type Bytes = Uint8Array<ArrayBuffer>;

const STD = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const URL_SAFE = /^[A-Za-z0-9_-]*$/;
const HEX = /^(?:[0-9a-f]{2})*$/;

function binary(raw: string): Bytes {
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function raw(bytes: Uint8Array): string {
  let text = "";
  for (const b of bytes) text += String.fromCharCode(b);
  return text;
}

/** Standard padded base64 to bytes; anything non-canonical is refused. */
export function fromBase64(text: string): Bytes {
  if (!STD.test(text)) throw new Error("bytes: bad base64");
  const bytes = binary(atob(text));
  if (toBase64(bytes) !== text) throw new Error("bytes: bad base64");
  return bytes;
}

// Small-order Ed25519 encodings, compared over the low 31 bytes and the top byte without its sign bit.
const SMALL_ORDER = new Set(
  [
    "00".repeat(32),
    "01" + "00".repeat(31),
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ec" + "ff".repeat(30) + "7f",
    "ed" + "ff".repeat(30) + "7f",
    "ee" + "ff".repeat(30) + "7f",
  ],
);
const FIELD = (1n << 255n) - 19n;

/** Raw 32-byte key from standard base64, or null when the text is anything else, a non-canonical y, or a small-order point. */
export function rawKey(text: string): Bytes | null {
  try {
    const key = fromBase64(text.trim());
    if (key.length !== 32) return null;
    let y = 0n;
    for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? key[i]! & 0x7f : key[i]!);
    if (y >= FIELD) return null;
    const masked = new Uint8Array(key);
    masked[31] = masked[31]! & 0x7f;
    return SMALL_ORDER.has(toHex(masked)) ? null : key;
  } catch {
    return null;
  }
}

/** Unpadded base64url to bytes; anything non-canonical is refused. */
export function fromBase64Url(text: string): Bytes {
  if (!URL_SAFE.test(text) || text.length % 4 === 1) throw new Error("bytes: bad base64url");
  const bytes = binary(atob(text.replaceAll("-", "+").replaceAll("_", "/")));
  if (toBase64Url(bytes) !== text) throw new Error("bytes: bad base64url");
  return bytes;
}

/** One compact JWS segment as PyJWT reads it: canonical base64url, up to two `=` allowed on a whole quantum. */
export function fromJwsSegment(text: string): Bytes {
  const stripped = text.replace(/={1,2}$/, "");
  if (stripped !== text && text.length % 4 !== 0) throw new Error("bytes: bad base64url");
  return fromBase64Url(stripped);
}

/** Standard padded base64. */
export function toBase64(bytes: Uint8Array): string {
  return btoa(raw(bytes));
}

/** Unpadded base64url. */
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Lowercase hex. */
export function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** Lowercase even-length hex to bytes. */
export function fromHex(hex: string): Bytes {
  if (!HEX.test(hex)) throw new Error("bytes: bad hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** ASCII text to bytes; any code unit above 0x7f is refused. */
export function ascii(text: string): Bytes {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c > 0x7f) throw new Error("bytes: not ASCII");
    out[i] = c;
  }
  return out;
}

/** The parts joined in order. */
export function concat(...parts: readonly Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** SHA-256 digest. */
export async function sha256(bytes: Bytes): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** Ed25519 verification of a raw 32-byte key and 64-byte signature; false on any failure, never throws. */
export async function verifyEd25519(publicKey: Bytes, signature: Bytes, message: Bytes): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
  } catch {
    return false;
  }
}
