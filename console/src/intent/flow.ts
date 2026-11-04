import { DeskError, type AgentStatus, type Draft, type DraftDenied, type IntentApi, type SignedIntent } from "./api";
import { intentBytes, toBase64, verifyState } from "./bytes";
import { toHex } from "../explorer/bytes";
import { checkWav } from "./wav";

export type Phase = "idle" | "busy" | "review" | "signed";

export interface IntentView {
  phase: Phase;
  status: string;
  draft: Draft | null;
  receipt: SignedIntent | null;
  funds: string;
  fundsOk: boolean;
  agent: AgentStatus | null;
}

/** Longest request the desk drafts, in characters. */
export const MAX_TEXT = 500;

const VERIFIED = "ok: cooperative";

/** True while Muse Spark is working on, or waiting for, a handed intent. */
export function runActive(agent: AgentStatus | null): boolean {
  return agent !== null && (agent.state === "quoting" || agent.state === "waiting" || agent.state === "confirming");
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function deskText(error: unknown): string {
  if (error instanceof DeskError && error.status === 503) return "Muse Spark is not configured on this desk.";
  return `Desk refused: ${message(error)}`;
}

/** The holder's payment intent, from words to a signed receipt and a handed-off run. */
export class IntentFlow {
  view: IntentView = { phase: "idle", status: "", draft: null, receipt: null, funds: "", fundsOk: false, agent: null };

  constructor(
    private readonly api: IntentApi,
    private readonly keys: CryptoKeyPair,
    private readonly render: (view: IntentView) => void,
    private readonly nowS: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  get agentActive(): boolean {
    return runActive(this.view.agent);
  }

  /** Drafts an intent from typed words. */
  async read(text: string): Promise<void> {
    if (!this.#canDraft()) return;
    const words = text.trim();
    if (words === "") return this.#set({ status: "Type or say the payment first." });
    if (words.length > MAX_TEXT) return this.#set({ status: `Keep it under ${MAX_TEXT} characters.` });
    await this.#draft(() => this.api.draftText(words));
  }

  /** Drafts an intent from a WAV clip, refused here when the desk would refuse it. */
  async clip(wav: ArrayBuffer): Promise<void> {
    if (!this.#canDraft()) return;
    try {
      checkWav(wav);
    } catch (error) {
      return this.#set({ status: `Clip refused before upload: ${message(error)}` });
    }
    await this.#draft(() => this.api.draftVoice(wav));
  }

  /** Signs the reviewed fields with this device's key and checks the bank statement. */
  async sign(): Promise<void> {
    const draft = this.view.draft;
    if (this.view.phase !== "review" || draft === null) return;
    this.#set({ phase: "busy", status: "Signing on this device." });
    let result;
    let hash: string;
    try {
      // The page signs the fields it shows, rebuilt here, never a server summary.
      const bytes = intentBytes(draft.intent);
      const signature = await crypto.subtle.sign({ name: "Ed25519" }, this.keys.privateKey, bytes);
      hash = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
      result = await this.api.sign(draft.intent, toBase64(signature));
    } catch (error) {
      return this.#set({ phase: "review", status: `Intent refused: ${message(error)}` });
    }
    if (result.status !== "signed") return this.#set({ phase: "review", status: `Intent refused: ${result.reason}` });
    const verdict = await verifyState(result.state, result.bank_key, hash, this.nowS());
    const fundsOk = verdict === VERIFIED;
    this.#set({
      phase: "signed",
      status: "Signed. The agent gets only the intent id.",
      receipt: result,
      fundsOk,
      funds: fundsOk ? "sufficient: desk-signed statement verified on this device." : `not verified: ${verdict}`,
    });
  }

  /** Drops the draft under review. */
  discard(): void {
    if (this.view.phase !== "review") return;
    this.#set({ phase: "idle", status: "", draft: null });
  }

  /** Hands Muse Spark the intent id, and nothing else, once the statement verified. */
  async handoff(): Promise<void> {
    const receipt = this.view.receipt;
    if (receipt === null || !this.view.fundsOk || this.agentActive || this.view.agent?.state === "done") {
      return this.render(this.view);
    }
    try {
      this.#set({ agent: await this.api.handoff(receipt.intent_id) });
    } catch (error) {
      this.#set({ status: deskText(error) });
    }
  }

  /** Follows the handed-off run while it is active. */
  async poll(): Promise<void> {
    if (!this.agentActive) return;
    try {
      this.#set({ agent: await this.api.agent() });
    } catch (error) {
      this.#set({ status: deskText(error) });
    }
  }

  #canDraft(): boolean {
    return this.view.phase !== "busy" && this.view.phase !== "signed";
  }

  async #draft(call: () => Promise<Draft | DraftDenied>): Promise<void> {
    this.#set({ phase: "busy", status: "Reading your request with Muse Spark.", draft: null });
    try {
      const answer = await call();
      if (answer.status === "drafted") {
        this.#set({ phase: "review", status: "Check every field. Signing binds exactly these.", draft: answer });
      } else {
        this.#set({ phase: "idle", status: `Not understood: ${answer.reason}` });
      }
    } catch (error) {
      this.#set({ phase: "idle", status: deskText(error) });
    }
  }

  #set(change: Partial<IntentView>): void {
    this.view = { ...this.view, ...change };
    this.render(this.view);
  }
}
