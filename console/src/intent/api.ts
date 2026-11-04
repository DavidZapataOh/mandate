import { toBase64Url, toHex } from "../explorer/bytes";
import type { BankState, IntentFields } from "./bytes";

export interface Draft {
  status: "drafted";
  transcript: string;
  intent: IntentFields;
}
export interface DraftDenied {
  status: "denied";
  transcript: string;
  reason: string;
}
export interface SignedIntent {
  status: "signed";
  intent_id: string;
  intent_hash: string;
  summary: string;
  evidence_ref: string;
  state: BankState;
  bank_key: string;
}
export interface Refused {
  status: "denied";
  reason: string;
}
export type AgentPhase = "idle" | "quoting" | "waiting" | "confirming" | "done" | "failed";
export interface AgentStatus {
  state: AgentPhase;
  intent_id: string | null;
  quote_id: string | null;
  detail: string;
}

/** A desk answer other than 2xx, with the desk's `error` text. */
export class DeskError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export interface IntentApi {
  draftText(text: string): Promise<Draft | DraftDenied>;
  draftVoice(wav: ArrayBuffer): Promise<Draft | DraftDenied>;
  sign(intent: IntentFields, signature: string): Promise<SignedIntent | Refused>;
  handoff(intentId: string): Promise<AgentStatus>;
  agent(): Promise<AgentStatus>;
}

const DEVICE_HEADER = "x-mandate-device-sig";
const DRAFT_DOMAIN = "mandate/intent-draft/v1";
const VOICE_DOMAIN = "mandate/intent-voice/v1";
const AGENT_DOMAIN = "mandate/agent-start/v1";

/**
 * Unpadded base64url Ed25519 signature over `<domain>\n<sha256 hex of body>`:
 * the proof the desk asks of a paired device before it spends a model call.
 */
export async function deviceProof(key: CryptoKey, domain: string, body: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
  const message = new TextEncoder().encode(`${domain}\n${digest}`);
  return toBase64Url(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, message)));
}

async function answer<T>(response: Response): Promise<T> {
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const error = typeof body === "object" && body !== null ? (body as { error?: unknown }).error : undefined;
    throw new DeskError(response.status, typeof error === "string" ? error : `HTTP ${response.status}`);
  }
  return body as T;
}

/**
 * The holder routes of the desk at `base` (same origin). Requests that make the
 * desk call a model carry a proof by `deviceKey`, the paired holder key, over
 * the exact bytes sent.
 */
export function httpIntentApi(base: string, deviceKey: CryptoKey, fetchFn: typeof fetch = fetch): IntentApi {
  const send = async <T>(path: string, type: string, body: Uint8Array<ArrayBuffer>, domain: string | null): Promise<T> => {
    const headers: Record<string, string> = { "content-type": type, accept: "application/json" };
    if (domain !== null) headers[DEVICE_HEADER] = await deviceProof(deviceKey, domain, body);
    return answer<T>(await fetchFn(`${base}${path}`, { method: "POST", headers, body }));
  };
  const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  return {
    draftText: (text) => send("/api/intent/draft", "application/json", json({ text }), DRAFT_DOMAIN),
    draftVoice: (wav) => send("/api/intent/voice", "audio/wav", new Uint8Array(wav), VOICE_DOMAIN),
    // The intent signature is its own proof; the desk checks it against the paired key.
    sign: (intent, signature) => send("/api/intent", "application/json", json({ intent, signature }), null),
    handoff: (intentId) => send("/api/agent/start", "application/json", json({ intent_id: intentId }), AGENT_DOMAIN),
    agent: async () => answer<AgentStatus>(await fetchFn(`${base}/api/agent`, { headers: { accept: "application/json" } })),
  };
}
