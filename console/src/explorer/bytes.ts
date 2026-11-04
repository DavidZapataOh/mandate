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
