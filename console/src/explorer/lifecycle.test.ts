import { describe, expect, it } from "vitest";
import { fromBase64 } from "./bytes";
import RECEIPT_ACH from "./__fixtures__/receipt-ach.json" with { type: "json" };
import LIFECYCLE from "./__fixtures__/lifecycle-ach.json" with { type: "json" };
import RECEIPT from "./__fixtures__/receipt.json" with { type: "json" };
import { GATE_KEY, resign } from "./__fixtures__/receipts";
import { lifecycleRows } from "./lifecycle";
import { disclosedOf } from "./verify";
import { parseReceipt } from "./receipt";

const KEY = fromBase64(GATE_KEY);

async function rows(value: unknown, receipt: unknown = RECEIPT_ACH) {
  const r = parseReceipt(receipt);
  const d = await disclosedOf(r, KEY);
  if (d === null) throw new Error("golden does not disclose");
  return lifecycleRows(value, r, d, KEY);
}

const clone = () => JSON.parse(JSON.stringify(LIFECYCLE));

describe("lifecycle", () => {
  it("lifecycle: a verified return reads SIMULATED RETURN", async () => {
    expect(await rows(LIFECYCLE)).toEqual([
      ["Requested", "200.00 USD"],
      ["Approved", "Gate certificate 00000000000000000000000000000002"],
      ["Processed", "SIMULATED RETURN R01 insufficient_fund at 2027-01-16T08:16:40Z; the money went back to the payer"],
      ["Sealed entry #2", `settlement · included under seal ${LIFECYCLE.events[0]!.seal.anchor_id}`],
      ["Sealed entry #3", `return · included under seal ${LIFECYCLE.events[1]!.seal.anchor_id}`],
    ]);
  });

  const flip = (sig: string) => (sig[0] === "A" ? "B" : "A") + sig.slice(1);

  it.each([
    ["an edited return code", (l: any) => (l.events[1].entry.body = l.events[1].entry.body.replace("R01", "R02")), "entry is not in the sealed registry"],
    ["a forged seal", (l: any) => (l.events[1].seal.signature = flip(l.events[1].seal.signature)), "seal is not signed by the gate key"],
  ])("lifecycle: refuses %s", async (_, edit, why) => {
    const value = clone();
    edit(value);
    const got = await rows(value);
    expect(got.find(([t]) => t === "Processed")?.[1]).toBe(`Unverified: ${why}`);
    expect(got).toContainEqual(["Sealed entry #3", `does not verify: ${why}`]);
  });

  it("an empty lifecycle claims no outcome", async () => {
    const value = { ...clone(), events: [] };
    expect((await rows(value)).find(([t]) => t === "Processed")?.[1]).toBe(
      "Accepted by the bank (pending_submission); not settled yet",
    );
  });

  // A lost answer reconciled after the return: the receipt seals the bank's own status, `returned`.
  const returnedReceipt = async () =>
    JSON.parse(
      await resign((p) => {
        p.bank = { ...(p.bank as object), status: "returned" };
      }, JSON.stringify(RECEIPT_ACH)),
    );

  it("lifecycle: a receipt sealed after its return reads the sealed return", async () => {
    const got = await rows(LIFECYCLE, await returnedReceipt());
    expect(got.find(([t]) => t === "Processed")?.[1]).toBe(
      "SIMULATED RETURN R01 insufficient_fund at 2027-01-16T08:16:40Z; the money went back to the payer",
    );
    expect(got).toContainEqual(["Sealed entry #3", `return · included under seal ${LIFECYCLE.events[1]!.seal.anchor_id}`]);
  });

  it("a receipt sealed after its return never reads as accepted, even before its entry arrives", async () => {
    const value = { ...clone(), events: [] };
    expect((await rows(value, await returnedReceipt())).find(([t]) => t === "Processed")?.[1]).toBe(
      "Returned by the bank before this receipt was sealed; the money went back to the payer",
    );
  });

  it("shows nothing for an account transfer", async () => {
    expect(await rows(LIFECYCLE, RECEIPT)).toEqual([]);
  });
});
