import { describe, expect, it } from "vitest";
import { ATTACK, CONFIRM, patch } from "../wire/__fixtures__/lines";
import { RECEIPT } from "./__fixtures__/receipts";
import { classify } from "./input";

describe("classify", () => {
  it("reads a payment id", () => {
    expect(classify("  pay:000001\n")).toEqual({ kind: "payment", id: "pay:000001" });
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
  it.each(["", "pay:1", "hello", "[1]", '{"v":1}'])("refuses %j", (text) => {
    expect(classify(text)).toEqual({ kind: "unknown", reason: "Paste a receipt, a certificate, a payment id or a console line" });
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
