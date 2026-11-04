import { describe, expect, it } from "vitest";
import { ATTACK, CONFIRM, patch } from "../wire/__fixtures__/lines";
import { RECEIPT } from "./__fixtures__/receipts";
import { classify } from "./input";

describe("classify", () => {
  it("reads a payment id", () => {
    expect(classify("  pay:000001\n")).toEqual({ kind: "payment", id: "pay:000001" });
  });
  it("reads a bank transfer id as a payment id", () => {
    expect(classify("account_transfer_7k9qe1ysdgqztnt63l7n")).toEqual({ kind: "payment", id: "account_transfer_7k9qe1ysdgqztnt63l7n" });
  });
  it("reads a sandbox bank transfer id as a payment id", () => {
    expect(classify("sandbox_account_transfer_astdbpezq3uovbhia1nb")).toEqual({
      kind: "payment", id: "sandbox_account_transfer_astdbpezq3uovbhia1nb",
    });
  });
  it.each([
    ["73fb45625595a413f1f2ee4ec0a19acb4bdf4709a1927856a9ee2f31a4c0391f", "73fb45625595a413f1f2ee4ec0a19acb4bdf4709a1927856a9ee2f31a4c0391f"],
    [" 52E9B189B7DB1F410229E8BB9A3A4A99D34E30523C3507480821839A3845069B\n", "52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b"],
    ["1".repeat(64), "1".repeat(64)],
  ])("reads %j as a hash, in lowercase", (text, hash) => {
    expect(classify(text)).toEqual({ kind: "hash", hash });
  });
  it("reads a certificate", () => {
    const token = JSON.parse(RECEIPT).certificate;
    expect(classify(token)).toEqual({ kind: "certificate", token });
  });
  it("reads a receipt", () => {
    expect(classify(RECEIPT)).toEqual({ kind: "receipt", value: JSON.parse(RECEIPT) });
  });
  it("finds the payment behind a confirmed desk line", () => {
    expect(classify(CONFIRM)).toEqual({ kind: "line", seq: 3, paymentId: "pay:000001" });
  });
  it("finds no payment behind an attack line", () => {
    expect(classify(ATTACK)).toEqual({ kind: "line", seq: 4, paymentId: null });
  });
  it.each(["", "pay:1", "hello", "[1]", '{"v":1}', "account_transfer_", "sandbox_account_", "account_transfer_a-b", `account_transfer_${"a".repeat(65)}`, "a".repeat(63), "a".repeat(65), `0x${"a".repeat(64)}`, "g".repeat(64)])("refuses %j", (text) => {
    expect(classify(text)).toEqual({ kind: "unknown", reason: "Paste a receipt, a certificate, a payment id, a receipt or action hash, or a console line" });
  });
  it("finds no payment behind a forged approval that carries a consent", () => {
    const forensic = {
      ...JSON.parse(ATTACK).forensic,
      policy: { policy_id: "desk", rule_id: "pay-with-consent" },
      consent: {
        amount_cents: 20000, currency: "USD", recipient: "evil-666", reference: "A-991", source: "checking-881",
        nonce: "atk00000000000000000000000000007", expires_at: 1800001600,
      },
    };
    const line = patch(ATTACK, { seq: 11, forensic }, { attack: "forged_approval", layer: "holder->gate", reason: "consent: bad signature" });
    expect(classify(line)).toEqual({ kind: "line", seq: 11, paymentId: null });
  });
  it("refuses a malformed console line", () => {
    expect(classify('{"v":3,"seq":1}')).toEqual({ kind: "unknown", reason: "This console line is malformed" });
  });
});
