import { describe, expect, it } from "vitest";
import { AUDITOR, RECEIPT, SANDBOX_RECEIPT, tamper } from "./__fixtures__/receipts";
import { carries, receiptHash } from "./lookup";
import { parseReceipt } from "./receipt";

const RECEIPT_HASH = "73fb45625595a413f1f2ee4ec0a19acb4bdf4709a1927856a9ee2f31a4c0391f";
const ACTION_HASH = "52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b";
const LEAF = "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87";
const receipt = (text: string) => parseReceipt(JSON.parse(text));

describe("receiptHash", () => {
  it("is the same for the holder copy and the auditor copy", async () => {
    expect(await receiptHash(receipt(RECEIPT).sd)).toBe(RECEIPT_HASH);
    expect(await receiptHash(receipt(AUDITOR).sd)).toBe(RECEIPT_HASH);
  });
  it("differs for another receipt", async () => {
    expect(await receiptHash(receipt(SANDBOX_RECEIPT).sd)).toBe(
      "ed243f55086c02b1ca4bdb338676e660e82167cfbbcf819b531b38e8dc9db17b",
    );
  });
});

describe("carries", () => {
  it.each([RECEIPT_HASH, ACTION_HASH])("finds %s in the receipt", async (hash) => {
    expect(await carries(receipt(AUDITOR), hash)).toBe(true);
  });
  it.each([LEAF, "ab".repeat(32)])("does not find %s", async (hash) => {
    expect(await carries(receipt(AUDITOR), hash)).toBe(false);
  });
  it("does not find this receipt's hashes in another receipt", async () => {
    expect(await carries(receipt(SANDBOX_RECEIPT), RECEIPT_HASH)).toBe(false);
    expect(await carries(receipt(SANDBOX_RECEIPT), ACTION_HASH)).toBe(false);
  });
  it("finds nothing in a receipt whose parts do not read", async () => {
    expect(await carries(receipt(tamper("sd", "é~", AUDITOR)), RECEIPT_HASH)).toBe(false);
    expect(await carries(receipt(tamper("certificate", "a.b.c", AUDITOR)), ACTION_HASH)).toBe(false);
  });
});
