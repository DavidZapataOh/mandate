import { DeskError, type AgentStatus, type Draft, type DraftDenied, type IntentApi, type Refused, type SignedIntent } from "../api";
import type { IntentFields } from "../bytes";
import { MARKER } from "../../wire/__fixtures__/lines";

export const ACME: IntentFields = { amount_cents: 20000, currency: "USD", recipient: "acme-991", reference: "A-991" };
export const HASH = "a7a12d73de0370d60b0ea24041a748ee6fc4db6974cf47b3b502f2c7d52b3ed8";
// Ed25519 seed 0x07 * 32; the bank statement and intent signature below were made by the desk's Python code.
export const SEED_PKCS8 = "302e020100300506032b657004220420" + "07".repeat(32);
export const SEED_PUBLIC = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";
export const INTENT_SIGNATURE = "2SQ9c7Bz07xobdfU3UdLip5UBujsuKGwwijJqIoAO8Ej4LPraf/DOm8vt2YxhQ8pGP1YORBpnhszspqsMXkXDQ==";
export const DRAFT: Draft = { status: "drafted", transcript: `${MARKER} Pay my Acme Corp bill A-991, 200 USD`, intent: ACME };
export const SIGNED: SignedIntent = {
  status: "signed",
  intent_id: "i:000001",
  intent_hash: HASH,
  summary: `${MARKER} Pay 200.00 USD to acme-991 (ref A-991) from checking-881`,
  evidence_ref: "ev:cooperative-signed:c97da00074742018dff37a1130a145f3",
  state: {
    subject: "checking-881", statement: "funds-sufficient", balance_cents: 50000, currency: "USD",
    nonce: HASH, issued_at: 1800001000, expires_at: 1800001300,
    signature: "RAC79J68Gcddcawo+K1fvgVWciw45j8gLz9+p/Jq/ZqcA2b61+etIxPm3cuBnG6/kUozZ5siIVeHoaLntI8EAA==",
  },
  bank_key: SEED_PUBLIC,
};

// Device proofs by the same seed over exact request bodies; derived with OpenSSL
// (`pkeyutl -sign -rawin`) and accepted by the desk's `_device_proved`.
export const DRAFT_BODY = '{"text":"Pay my Acme Corp bill A-991, 200 USD"}';
export const DRAFT_PROOF = "u_BTjVuIb3_ENxffqoAnYitqAcjhc_Eqnm1hT2pY7KHUoOY9ZvFg22BNdxm6GLEIRwsq2tVzJAZckF0t2I2EDA";
export const START_BODY = '{"intent_id":"i:000001"}';
export const START_PROOF = "qVxaLKHX2KpRx5u_ScTrlsi-7YF80CZE93GQJjHL2xyyJw_YfMgnu4kybHKS-uRDmoCeO8qKHRyyTZE3slixDw";
/** Over demo/voice/pay-acme.wav, sha256 b68becbe15942b9434136c0a3e81064506e075ce07bfcb526aaa9d7edbc95e2f. */
export const CLIP_PROOF = "XxDTmM4avc3k1cnTW1lAl9AKMGHQ8yCnnPVK5rukF2KT_0Vffx-WTdXnCoVI_yNy1fsg9KgB7lZt1ZYc6T6RCw";

export async function seedKeys(): Promise<CryptoKeyPair> {
  const privateKey = await crypto.subtle.importKey("pkcs8", Buffer.from(SEED_PKCS8, "hex"), { name: "Ed25519" }, false, ["sign"]);
  const publicKey = await crypto.subtle.importKey("raw", Buffer.from(SEED_PUBLIC, "base64"), { name: "Ed25519" }, true, ["verify"]);
  return { privateKey, publicKey };
}

type Answer<T> = T | DeskError;

/** Test fake of the desk's holder routes: queued answers, recorded calls. */
export class FakeDesk implements IntentApi {
  calls: unknown[][] = [];
  drafts: Answer<Draft | DraftDenied>[] = [];
  signs: Answer<SignedIntent | Refused>[] = [];
  agents: Answer<AgentStatus>[] = [];

  #next<T>(queue: Answer<T>[]): Promise<T> {
    const answer = queue.shift();
    if (answer === undefined) throw new Error("FakeDesk: no answer queued");
    return answer instanceof DeskError ? Promise.reject(answer) : Promise.resolve(answer);
  }

  draftText(text: string) {
    this.calls.push(["draftText", text]);
    return this.#next(this.drafts);
  }
  draftVoice(wav: ArrayBuffer) {
    this.calls.push(["draftVoice", wav.byteLength]);
    return this.#next(this.drafts);
  }
  sign(intent: IntentFields, signature: string) {
    this.calls.push(["sign", intent, signature]);
    return this.#next(this.signs);
  }
  handoff(intentId: string) {
    this.calls.push(["handoff", intentId]);
    return this.#next(this.agents);
  }
  agent() {
    this.calls.push(["agent"]);
    return this.#next(this.agents);
  }
}
