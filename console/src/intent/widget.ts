import { formatAmount } from "./bytes";
import { runActive, type IntentFlow, type IntentView } from "./flow";

/** Captures one spoken clip as the desk's WAV. */
export interface Recorder {
  start(): Promise<void>;
  stop(): Promise<ArrayBuffer>;
}

function el<T extends HTMLElement = HTMLElement>(doc: Document, id: string): T {
  const found = doc.getElementById(id);
  if (found === null) throw new Error(`holder page: #${id} missing`);
  return found as T;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const REFUSALS = ["Desk refused: ", "Clip refused before upload: ", "Intent refused: ", "Not understood: "];

/** "refused" when a holder status sentence reports a refusal, else "". */
export function toneOf(status: string): string {
  return REFUSALS.some((prefix) => status.startsWith(prefix)) ? "refused" : "";
}

/** Writes the view into the holder page, every desk or model string as text. */
export function renderIntent(doc: Document, view: IntentView): void {
  const text = (id: string, value: string) => {
    el(doc, id).textContent = value;
  };
  el(doc, "holder").dataset.phase = view.phase;
  text("intent-status", view.status);
  el(doc, "intent-status").dataset.tone = toneOf(view.status);
  const locked = view.phase === "busy" || view.phase === "signed";
  for (const id of ["intent-text", "intent-read", "intent-record", "intent-file"]) {
    el<HTMLInputElement>(doc, id).disabled = locked;
  }

  const draft = view.draft;
  // Once signed, the fields stay beside the receipt as what was signed, without the controls.
  const signed = view.phase === "signed";
  el(doc, "intent-review").hidden = draft === null;
  el(doc, "intent-sign").hidden = signed;
  el(doc, "intent-discard").hidden = signed;
  text("review-amount", draft ? formatAmount(draft.intent.amount_cents, draft.intent.currency) : "");
  text("review-recipient", draft?.intent.recipient ?? "");
  text("review-reference", draft?.intent.reference ?? "");
  text("review-heard", draft?.transcript ?? "");
  const reviewing = view.phase === "review";
  el<HTMLButtonElement>(doc, "intent-sign").disabled = !reviewing;
  el<HTMLButtonElement>(doc, "intent-discard").disabled = !reviewing;

  const receipt = view.receipt;
  el(doc, "intent-receipt").hidden = receipt === null;
  text("receipt-id", receipt?.intent_id ?? "");
  text("receipt-hash", receipt?.intent_hash ?? "");
  text("receipt-funds", receipt ? view.funds : "");
  el(doc, "receipt-funds").dataset.verified = String(receipt !== null && view.fundsOk);
  text("receipt-evidence", receipt?.evidence_ref ?? "");
  const finished = view.agent?.state === "done";
  el<HTMLButtonElement>(doc, "intent-handoff").disabled = !view.fundsOk || runActive(view.agent) || finished;
  text("agent-state", view.agent?.detail ?? "");
  el(doc, "agent-state").dataset.tone = view.agent?.state === "failed" ? "refused" : "";
}

/** Wires the holder page's controls to the flow and follows the agent's run. */
export function bindIntent(doc: Document, flow: IntentFlow, recorder: Recorder | null, pollMs = 1000): void {
  const status = el(doc, "intent-status");
  const record = el<HTMLButtonElement>(doc, "intent-record");
  const file = el<HTMLInputElement>(doc, "intent-file");

  const say = (words: string) => {
    status.textContent = words;
    status.dataset.tone = toneOf(words);
  };
  record.hidden = recorder === null;
  // A draft started mid-recording would lock the Stop button with the mic still open.
  let recording = false;

  el<HTMLFormElement>(doc, "intent-form").addEventListener("submit", (event) => {
    event.preventDefault();
    if (!recording) void flow.read(el<HTMLTextAreaElement>(doc, "intent-text").value);
  });
  const pressed = (on: boolean) => {
    recording = on;
    record.textContent = on ? "Stop" : "Record";
    record.setAttribute("aria-pressed", String(on));
  };
  record.addEventListener("click", async () => {
    if (recorder === null) return;
    if (!recording) {
      try {
        await recorder.start();
      } catch (error) {
        say(`Microphone unavailable: ${message(error)}`);
        return;
      }
      pressed(true);
      say("Recording. Press Stop when done.");
      return;
    }
    pressed(false);
    let wav: ArrayBuffer;
    try {
      wav = await recorder.stop();
    } catch (error) {
      say(`Microphone unavailable: ${message(error)}`);
      return;
    }
    await flow.clip(wav);
  });

  file.addEventListener("change", async () => {
    const chosen = file.files?.[0];
    if (chosen === undefined || recording) return;
    const wav = await chosen.arrayBuffer();
    file.value = "";
    await flow.clip(wav);
  });

  el(doc, "intent-sign").addEventListener("click", () => void flow.sign());
  el(doc, "intent-discard").addEventListener("click", () => flow.discard());
  const handoff = el<HTMLButtonElement>(doc, "intent-handoff");
  handoff.addEventListener("click", () => {
    // Held off until the desk answers, so one click starts one run.
    handoff.disabled = true;
    void flow.handoff();
  });
  setInterval(() => void flow.poll(), pollMs);
}
