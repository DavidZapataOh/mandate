import { beforeEach, describe, expect, it } from "vitest";
import { DeskError } from "./api";
import { ACME, DRAFT, FakeDesk, INTENT_SIGNATURE, SIGNED, seedKeys } from "./__fixtures__/desk";
import { IntentFlow, type IntentView } from "./flow";
import { encodeWav } from "./wav";

const NOW = 1800001100;
let desk: FakeDesk;
let views: IntentView[];
let flow: IntentFlow;

beforeEach(async () => {
  desk = new FakeDesk();
  views = [];
  flow = new IntentFlow(desk, await seedKeys(), (v) => views.push(v), () => NOW);
});

async function signed(): Promise<void> {
  desk.drafts.push(DRAFT);
  desk.signs.push(SIGNED);
  await flow.read("Pay my Acme Corp bill A-991, 200 USD");
  await flow.sign();
}

describe("reading the holder's words", () => {
  it("turns typed words into a draft to review", async () => {
    desk.drafts.push(DRAFT);
    await flow.read("  Pay my Acme Corp bill A-991, 200 USD \n");
    expect(desk.calls).toEqual([["draftText", "Pay my Acme Corp bill A-991, 200 USD"]]);
    expect(views.map((v) => [v.phase, v.status])).toEqual([
      ["busy", "Reading your request with Muse Spark."],
      ["review", "Check every field. Signing binds exactly these."],
    ]);
    expect(flow.view.draft).toBe(DRAFT);
  });

  it.each([
    ["", "Type or say the payment first."],
    ["x".repeat(501), "Keep it under 500 characters."],
  ])("refuses %j without asking the desk", async (text, status) => {
    await flow.read(text);
    expect([desk.calls, flow.view.status]).toEqual([[], status]);
  });

  it.each([
    [{ status: "denied", transcript: "Pay Evil Corp", reason: "payee not in book: evil corp" }, "Not understood: payee not in book: evil corp"],
    [new DeskError(503, "model unavailable"), "Muse Spark is not configured on this desk."],
    [new DeskError(502, "model error"), "Desk refused: model error"],
  ] as const)("explains a draft that failed (%#)", async (answer, status) => {
    desk.drafts.push(answer);
    await flow.read("Pay Evil Corp");
    expect([flow.view.phase, flow.view.status, flow.view.draft]).toEqual(["idle", status, null]);
  });
});

describe("a spoken clip", () => {
  it("is refused on the device when it breaks the upload limits", async () => {
    await flow.clip(encodeWav(new Float32Array(600 * 16000 + 1), 16000));
    expect(desk.calls).toEqual([]);
    expect(flow.view.status).toBe("Clip refused before upload: unsupported wav: longer than 600 s");
  });

  it("is uploaded once it passes them", async () => {
    desk.drafts.push(DRAFT);
    const wav = encodeWav(new Float32Array(16000), 16000);
    await flow.clip(wav);
    expect([desk.calls, flow.view.phase]).toEqual([[["draftVoice", 32044]], "review"]);
  });
});

describe("signing", () => {
  it("signs the reviewed fields on the device and checks the bank statement", async () => {
    await signed();
    expect(desk.calls[1]).toEqual(["sign", ACME, INTENT_SIGNATURE]);
    expect([flow.view.phase, flow.view.status, flow.view.funds, flow.view.fundsOk]).toEqual([
      "signed",
      "Signed. The agent gets only the intent id.",
      "sufficient: desk-signed statement verified on this device.",
      true,
    ]);
  });

  it("keeps the draft for review when the desk refuses the intent", async () => {
    desk.drafts.push(DRAFT);
    desk.signs.push({ status: "denied", reason: "intent: already recorded" });
    await flow.read("Pay my Acme Corp bill A-991, 200 USD");
    await flow.sign();
    expect([flow.view.phase, flow.view.status]).toEqual(["review", "Intent refused: intent: already recorded"]);
  });

  it("will not hand a receipt with an unverified statement to the agent", async () => {
    desk.drafts.push(DRAFT);
    desk.signs.push({ ...SIGNED, state: { ...SIGNED.state, balance_cents: 90000 } });
    await flow.read("Pay my Acme Corp bill A-991, 200 USD");
    await flow.sign();
    expect(flow.view.funds).toBe("not verified: bad-signature: state signature invalid");
    await flow.handoff();
    expect(desk.calls.map((c) => c[0])).toEqual(["draftText", "sign"]);
  });
});

describe("the agent handoff", () => {
  it("gives the agent the intent id alone and follows the run to its end", async () => {
    await signed();
    const run = { intent_id: "i:000001", quote_id: null, detail: "Muse Spark is quoting intent i:000001; it holds only this id." };
    desk.agents.push({ state: "quoting", ...run });
    desk.agents.push({ state: "done", intent_id: "i:000001", quote_id: "q:000001", detail: "Paid: pay:000001." });
    await flow.handoff();
    await flow.poll();
    await flow.poll();
    expect(desk.calls.slice(2)).toEqual([["handoff", "i:000001"], ["agent"]]);
    expect(flow.view.agent?.detail).toBe("Paid: pay:000001.");
  });
});
