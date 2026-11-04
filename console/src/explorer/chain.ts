import { ascii, concat, fromBase64, fromHex, fromJwsSegment, sha256, toHex, type Bytes } from "./bytes";
import { canonicalJson, sha256Hex } from "./canon";
import { readJws } from "./jws";
import type { Cava, Entry, Proof, ReasoningAnchor, ReceiptConsent, Seal } from "./receipt";

export const EVENT_TYPE = "urn:mandate:secevent:cert:v1";
const HEX64 = /^[0-9a-fA-F]{64}$/;
// Python's strict UTF-8 encoder raises on these; TextEncoder would silently replace them.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** CAVA canonical bytes as gate/cava.py writes them. */
export function cavaJson(cava: Cava): string {
  return canonicalJson(cava);
}

/** Signature-checked certificate subject (gate/certs.py read_claims), or a reason. */
export async function readClaims(token: string, gateKey: Bytes): Promise<{ claims: Record<string, unknown> } | { reason: string }> {
  if (gateKey.length !== 32) return { reason: "malformed: bad public key" };
  const read = await readJws(token, gateKey, false);
  if (read === "bad-signature") return { reason: "bad-signature: eddsa mismatch" };
  if (read === "malformed") return { reason: "malformed: token undecodable" };
  const events = read.payload.events;
  const subject = isObject(events) && Object.hasOwn(events, EVENT_TYPE) ? events[EVENT_TYPE] : undefined;
  if (!isObject(subject)) return { reason: "malformed: token undecodable" };
  return { claims: subject };
}

/** The certificate's `jti`; read it only after its signature verified. Null when undecodable. */
export function certificateId(token: string): string | null {
  const segments = token.split(".");
  if (segments.length !== 3) return null;
  try {
    const payload: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromJwsSegment(segments[1]!)));
    return isObject(payload) && typeof payload.jti === "string" ? payload.jti : null;
  } catch {
    return null;
  }
}

const token = (s: unknown) => typeof s === "string" && /^[\x21-\x7e]+$/.test(s);
const count = (n: unknown, minimum: number) => Number.isSafeInteger(n) && (n as number) >= minimum;

/** gate/consent.py consent_bytes over the seven signed fields. */
export function consentBytes(c: ReceiptConsent): Bytes {
  if (![c.currency, c.recipient, c.reference, c.source, c.nonce].every(token) || !count(c.amount_cents, 1) || !count(c.expires_at, 0)) {
    throw new Error("consent: malformed");
  }
  const { amount_cents, currency, expires_at, nonce, recipient, reference, source } = c;
  return ascii(`consent/v1:${canonicalJson({ amount_cents, currency, expires_at, nonce, recipient, reference, source })}`);
}

/** gate/registry.py leaf digest (hex) of one entry. */
export async function leafHash(entry: Entry): Promise<string> {
  return sha256Hex(concat(ascii("leaf/v1:"), ascii(canonicalJson({ body: entry.body, kind: entry.kind, seq: entry.seq }))));
}

/** gate/registry.py verify_inclusion's recomputed root, or null when the proof is malformed. */
export async function rootOf(proof: Proof): Promise<string | null> {
  if (proof.leaves < 1 || proof.seq < 1 || proof.seq > proof.leaves) return null;
  if (!HEX64.test(proof.leaf) || !proof.siblings.every((s) => HEX64.test(s))) return null;
  let current = fromHex(proof.leaf.toLowerCase());
  let index = proof.seq - 1;
  for (const s of proof.siblings) {
    const sibling = fromHex(s.toLowerCase());
    current = await sha256(concat(ascii("node/v1:"), index % 2 === 0 ? current : sibling, index % 2 === 0 ? sibling : current));
    index = Math.floor(index / 2);
  }
  return toHex(current);
}

/** gate/registry.py Anchor.signable_bytes of a seal. */
export function sealBytes(seal: Seal): Bytes {
  return ascii(`anchor/v1:${canonicalJson([seal.anchor_id, seal.root, seal.seq_from, seal.seq_to, seal.ts, seal.v])}`);
}

/** gate/anchor_public.py anchor_digest (hex): the digest a public timestamp of this gate's seal commits to. */
export async function anchorDigest(seal: Seal, gateKey: Bytes): Promise<string> {
  return toHex(await sha256(concat(ascii("mandate-anchor/v1:"), gateKey, sealBytes(seal), fromBase64(seal.signature))));
}

/**
 * swarm/meta_client.py reasoning_commitment over encrypted reasoning blobs. Throws `reasoning: malformed blob` for
 * an empty blob, one with a newline (check_blob) or one Python cannot encode as UTF-8: each would let two blob
 * lists share one commitment.
 */
export async function reasoningCommitment(blobs: readonly string[]): Promise<string> {
  if (blobs.some((b) => b.length === 0 || b.includes("\n") || LONE_SURROGATE.test(b))) throw new Error("reasoning: malformed blob");
  const enc = new TextEncoder();
  return toHex(await sha256(concat(ascii(`mandate/reasoning/v1\n${blobs.length}\n`), ...blobs.map((b) => enc.encode(`${b}\n`)))));
}

/** swarm/anchor.py ReasoningAnchor.digest. */
export async function reasoningAnchorDigest(anchor: ReasoningAnchor): Promise<string> {
  const reasoning = await reasoningCommitment(anchor.blobs);
  return sha256Hex(`mandate/anchor/v1\n${canonicalJson({ model: anchor.model, reasoning, response_id: anchor.response_id })}`);
}
