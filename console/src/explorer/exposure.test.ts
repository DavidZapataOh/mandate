import { describe, expect, it } from "vitest";
import { fromBase64 } from "./bytes";
import { AUDITOR, CONSENT_KEY, GATE_KEY, HOLDER_KEY, RECEIPT } from "./__fixtures__/receipts";
import { exposure, NEVER_IN_A_RECEIPT, WITHHELD } from "./exposure";
import { parseReceipt, type Receipt } from "./receipt";
import { disclosedOf } from "./verify";

const rows = async (r: Receipt) => exposure(r, (await disclosedOf(r, fromBase64(GATE_KEY)))!);

describe("exposure", () => {
  it("lists what the holder copy discloses", async () => {
    expect(await rows(parseReceipt(JSON.parse(RECEIPT)))).toEqual([
      ["Amount", "200.00 USD"],
      ["Payee account", "acme-991"],
      ["Debit account", "checking-881"],
      ["Reference", "A-991"],
      ["Payment and quote ids", "pay:000001, q:000001"],
      ["Consent key (this payment only)", "k9ufLuD3456UL7WUQRkL8gucQ8/MigUaFSSZzzkrejc="],
      ["Holder public key", "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q="],
      ["Sealed at (unix seconds)", "1800001000"],
      ["Bank transfer", "SIMULATED pay:000001 (complete)"],
    ]);
  });

  it("names every field the auditor copy withholds", async () => {
    const auditor = await rows(parseReceipt(JSON.parse(AUDITOR)));
    expect(auditor.slice(0, 4)).toEqual([
      ["Amount", WITHHELD],
      ["Payee account", WITHHELD],
      ["Debit account", WITHHELD],
      ["Reference", WITHHELD],
    ]);
    expect(auditor.slice(5, 7)).toEqual([
      ["Consent key (this payment only)", CONSENT_KEY],
      ["Holder public key", WITHHELD],
    ]);
    expect(JSON.stringify(auditor)).not.toContain(HOLDER_KEY);
  });

  it("names encrypted reasoning when the receipt carries an anchor", async () => {
    const r = parseReceipt({ ...JSON.parse(RECEIPT), reasoning: { v: 1, model: "muse-spark-1.3", response_id: "resp_1", blobs: ["a", "b"] } });
    expect(await rows(r)).toContainEqual(["Encrypted model reasoning", "2 blob(s) from muse-spark-1.3"]);
  });

  it("names the bank that holds a sandbox transfer", async () => {
    const r = parseReceipt(JSON.parse(RECEIPT));
    const d = (await disclosedOf(r, fromBase64(GATE_KEY)))!;
    const bank = { rail: "sandbox" as const, provider: "increase", transfer_id: "account_transfer_x", status: "complete", idempotency_key: "k" };
    expect(exposure(r, { ...d, bank })).toContainEqual(["Bank transfer", "SANDBOX increase account_transfer_x (complete)"]);
  });

  it("says no receipt carries the bank API key", () => {
    expect(NEVER_IN_A_RECEIPT.at(-1)).toBe("The bank API key");
  });

  it("pads cents", async () => {
    const r = parseReceipt(JSON.parse(RECEIPT));
    const d = (await disclosedOf(r, fromBase64(GATE_KEY)))!;
    expect(exposure(r, { ...d, consent: { ...d.consent, amount_cents: 7 } })[0]).toEqual(["Amount", "0.07 USD"]);
  });
});
