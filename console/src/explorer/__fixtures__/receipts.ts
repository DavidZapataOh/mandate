import auditor from "./auditor.json" with { type: "json" };
import golden from "./receipt.json" with { type: "json" };
import { ascii, fromBase64Url, toBase64 } from "../bytes";
import { disclosureDigest, readDisclosure } from "../sdjwt";

// Test data only: receipts the Python desk issued with fixed test keys and salts.
export const GATE_KEY = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
export const HOLDER_KEY = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";
export const CONSENT_KEY = "k9ufLuD3456UL7WUQRkL8gucQ8/MigUaFSSZzzkrejc=";
export const FIXTURE_SIGNATURE =
  "un4ZKczA3s72LLDWOPKsGnVpPA5cywTHLY1Zn_selaZxeaxFBoWVt0wCrY_DlGeEgeEv0qQxcuNgBhGiRqzCDw";
/** Every field disclosed (the holder copy). */
export const RECEIPT = JSON.stringify(golden);
/** No personal field disclosed (what the receipt route serves). */
export const AUDITOR = JSON.stringify(auditor);
/** The action and consent the golden's disclosures carry. */
export const CAVA = {
  category: "payments", evidence_refs: ["q:000001"], executable: "bank.pay",
  freshness: { nonce: "00000000000000000000000000000002", timestamp: 1800001000 }, operation: "transfer",
  reversible: false, runtime: "mcp", targets: ["amount:USD:20000", "from:checking-881", "ref:A-991", "to:acme-991"],
  version: "cava/1",
};
export const CONSENT = {
  amount_cents: 20000, currency: "USD", recipient: "acme-991", reference: "A-991", source: "checking-881",
  nonce: "00000000000000000000000000000001", expires_at: 1800001600,
  signature: "OORzeXDe6eaiUsW4PdqrQGhplcplmWCgI+yt3WYVkQR34lDISLG3GHAMrfd0amy/IncXYk95hGubzPgB5jg+AQ==",
  consent_key: CONSENT_KEY,
  holder_key: HOLDER_KEY,
  key_signature: "Y9mn3uyjzxkfa7dU2VaNj5Qd59KrV+EuE/HAsQNq3Bs8j7Gf2oQTM4nW+5I73qc/wAKepMESV94VRMvga8YFBg==",
};
const SEED_PKCS8 = "302e020100300506032b657004220420" + "01".repeat(32);

/** The golden receipt with one change applied at a dotted path. */
export function tamper(path: string, value: unknown, text: string = RECEIPT): string {
  const receipt = JSON.parse(text);
  const keys = path.split(".");
  let at = receipt;
  for (const key of keys.slice(0, -1)) at = at[key];
  at[keys.at(-1)!] = value;
  return JSON.stringify(receipt);
}

const b64u = (bytes: Uint8Array) => {
  let raw = "";
  for (const b of bytes) raw += String.fromCharCode(b);
  return btoa(raw).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
};
const newDisclosure = (name: string, value: unknown) => b64u(ascii(JSON.stringify(["AAAAAAAAAAAAAAAAAAAAAA", name, value])));
const parts = (text: string) => {
  const sd: string = JSON.parse(text).sd;
  const [token, ...rest] = sd.split("~");
  return { token: token!, disclosures: rest.slice(0, -1) };
};

async function gateSign(input: string): Promise<string> {
  const pkcs8 = new Uint8Array(SEED_PKCS8.match(/../g)!.map((h) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  return b64u(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, ascii(input))));
}

/** The golden with one disclosure swapped for one the gate never signed. */
export function forge(name: string, value: unknown): string {
  const { token, disclosures } = parts(RECEIPT);
  const swapped = disclosures.map((d) => (readDisclosure(d)?.name === name ? newDisclosure(name, value) : d));
  return tamper("sd", [token, ...swapped, ""].join("~"));
}

/** The golden re-issued by the gate key itself with one disclosed value changed. */
export async function regate(name: string, value: unknown): Promise<string> {
  return reissue({ [name]: value });
}

/** The golden re-issued by the gate key itself with several disclosed values changed. */
export async function reissue(values: Record<string, unknown>): Promise<string> {
  const { token, disclosures } = parts(RECEIPT);
  const [header, body] = token.split(".");
  const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(body!)));
  const out: string[] = [];
  for (const d of disclosures) {
    const name = readDisclosure(d)?.name ?? "";
    if (!Object.hasOwn(values, name)) {
      out.push(d);
      continue;
    }
    const fresh = newDisclosure(name, values[name]);
    const [was, now] = [await disclosureDigest(d), await disclosureDigest(fresh)];
    for (const obj of [payload.cava, payload.consent]) {
      obj._sd = obj._sd.map((x: string) => (x === was ? now : x)).sort();
    }
    out.push(fresh);
  }
  const input = `${header}.${b64u(ascii(JSON.stringify(payload)))}`;
  return tamper("sd", [`${input}.${await gateSign(input)}`, ...out, ""].join("~"));
}

const seedPkcs8 = (seed: number) =>
  new Uint8Array(("302e020100300506032b657004220420" + seed.toString(16).padStart(2, "0").repeat(32)).match(/../g)!.map((h) => parseInt(h, 16)));

/** Standard base64 Ed25519 signature by the key of seed `bytes([seed]) * 32` (0x81: the one-time consent key, 0x02: the paired holder key). */
export async function seedSign(seed: number, message: Uint8Array<ArrayBuffer>): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", seedPkcs8(seed), { name: "Ed25519" }, false, ["sign"]);
  return toBase64(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, message)));
}

/** Standard base64 public key of seed `bytes([seed]) * 32`. */
export async function seedPublicKey(seed: number): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", seedPkcs8(seed), { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return toBase64(fromBase64Url(jwk.x!));
}

/** A compact JWT the gate key signs over any header and payload text. */
export async function gateToken(header: string, payload: string): Promise<string> {
  const input = `${b64u(ascii(header))}.${b64u(ascii(payload))}`;
  return `${input}.${await gateSign(input)}`;
}

/** A Disclosure text the tests digest into a gate-signed payload. */
export function disclosureText(name: unknown, value: unknown, salt: unknown = "AAAAAAAAAAAAAAAAAAAAAA"): string {
  return b64u(ascii(JSON.stringify([salt, name, value])));
}

/** The golden re-issued by the gate key with its signed payload edited; the Disclosures stay. */
export async function resign(edit: (payload: Record<string, unknown>) => void): Promise<string> {
  const { token, disclosures } = parts(RECEIPT);
  const [header, body] = token.split(".");
  const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(body!)));
  edit(payload);
  const input = `${header}.${b64u(ascii(JSON.stringify(payload)))}`;
  return tamper("sd", [`${input}.${await gateSign(input)}`, ...disclosures, ""].join("~"));
}
