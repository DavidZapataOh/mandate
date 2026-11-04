import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DRAFT, FakeDesk, SIGNED, seedKeys } from "./__fixtures__/desk";
import { IntentFlow } from "./flow";
import { bindIntent, renderIntent, type Recorder } from "./widget";

// Vitest runs from the console project root.
const PAGE = readFileSync(join(process.cwd(), "holder.html"), "utf8");
const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

let desk: FakeDesk;
let flow: IntentFlow;

beforeEach(async () => {
  document.documentElement.innerHTML = PAGE.replace(/<script[^>]*><\/script>/, "");
  desk = new FakeDesk();
  flow = new IntentFlow(desk, await seedKeys(), (v) => renderIntent(document, v), () => 1800001100);
  renderIntent(document, flow.view);
});

describe("holder page", () => {
  it("starts with only the request form", () => {
    expect([$("intent-review").hidden, $("intent-receipt").hidden, $("intent-status").textContent]).toEqual([true, true, ""]);
  });

  it("shows the parsed fields resolved against the payee book", async () => {
    bindIntent(document, flow, null);
    desk.drafts.push(DRAFT);
    $("intent-text").value = "Pay my Acme Corp bill A-991, 200 USD";
    $("intent-read").click();
    await settle();
    const shown = ["review-amount", "review-recipient", "review-reference", "review-heard"].map((id) => $(id).textContent);
    expect(shown).toEqual(["200.00 USD", "acme-991", "A-991", DRAFT.transcript]);
    expect([$("intent-review").hidden, $("intent-sign").disabled]).toEqual([false, false]);
  });

  it("shows the receipt and enables the handoff once the statement verifies", async () => {
    bindIntent(document, flow, null);
    desk.drafts.push(DRAFT);
    desk.signs.push(SIGNED);
    await flow.read("Pay my Acme Corp bill A-991, 200 USD");
    $("intent-sign").click();
    await vi.waitFor(() => expect($("intent-receipt").hidden).toBe(false));
    const shown = ["receipt-id", "receipt-hash", "receipt-funds", "receipt-evidence"].map((id) => $(id).textContent);
    expect(shown).toEqual([
      "i:000001",
      SIGNED.intent_hash,
      "Funds sufficient: desk-signed statement verified on this device.",
      "ev:cooperative-signed:c97da00074742018dff37a1130a145f3",
    ]);
    expect([$("intent-review").hidden, $("intent-sign").hidden, $("intent-discard").hidden]).toEqual([false, true, true]);
    expect([$("intent-handoff").disabled, $("intent-read").disabled]).toEqual([false, true]);
    expect([$("holder").dataset.phase, $("receipt-funds").dataset.verified]).toEqual(["signed", "true"]);
  });

  it("renders a hostile transcript as text", async () => {
    desk.drafts.push({ ...DRAFT, transcript: "<img src=x onerror=window.pwned=1>" });
    await flow.read("anything");
    expect($("review-heard").textContent).toBe("<img src=x onerror=window.pwned=1>");
    expect(document.querySelector("#review-heard img")).toBeNull();
  });

  it("records, stops and uploads the clip through the same checks", async () => {
    const wav = new ArrayBuffer(8);
    const recorder: Recorder = { start: vi.fn(async () => {}), stop: vi.fn(async () => wav) };
    bindIntent(document, flow, recorder);
    $("intent-record").click();
    await settle();
    expect([$("intent-record").textContent, $("intent-status").textContent]).toEqual(["Stop", "Recording. Press Stop when done."]);
    $("intent-record").click();
    await settle();
    expect($("intent-status").textContent).toBe("Clip refused before upload: unsupported wav: not a wav file");
    expect(desk.calls).toEqual([]);
  });

  it("says when the microphone is unavailable", async () => {
    const recorder: Recorder = { start: async () => Promise.reject(new Error("Permission denied")), stop: async () => new ArrayBuffer(0) };
    bindIntent(document, flow, recorder);
    $("intent-record").click();
    await settle();
    expect([$("intent-record").textContent, $("intent-status").textContent]).toEqual(["Record", "Microphone unavailable: Permission denied"]);
  });

  it("marks a refused request, and only a refused one, as a refusal", async () => {
    bindIntent(document, flow, null);
    await flow.read("");
    expect($("intent-status").dataset.tone).toBe("");
    await flow.clip(new ArrayBuffer(8));
    expect($("intent-status").dataset.tone).toBe("refused");
    desk.drafts.push(DRAFT);
    await flow.read("Pay my Acme Corp bill A-991, 200 USD");
    expect($("intent-status").dataset.tone).toBe("");
  });

  it("marks a failed agent run as a refusal and a waiting one as progress", () => {
    const run = { intent_id: "i:000001", quote_id: "q:000001" };
    renderIntent(document, { ...flow.view, agent: { ...run, state: "waiting", detail: "Quote q:000001 is waiting for your approval." } });
    expect($("agent-state").dataset.tone).toBe("");
    renderIntent(document, { ...flow.view, agent: { ...run, state: "failed", detail: "Not paid: amount differs from intent." } });
    expect($("agent-state").dataset.tone).toBe("refused");
  });

  it("hides the record button without a recorder", () => {
    bindIntent(document, flow, null);
    expect($("intent-record").hidden).toBe(true);
  });
});
