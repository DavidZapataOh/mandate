import { describe, expect, it } from "vitest";
import { ACME, HASH, INTENT_SIGNATURE, SEED_PKCS8, SEED_PUBLIC, SIGNED } from "./__fixtures__/desk";
import { formatAmount, fromBase64, intentBytes, stateBytes, toBase64, verifyState } from "./bytes";

const STATE = SIGNED.state;
const decode = (b: Uint8Array) => new TextDecoder().decode(b);

describe("intent bytes", () => {
  it("are byte-identical to the desk's intent/v1 bytes", async () => {
    const bytes = intentBytes(ACME);
    expect(decode(bytes)).toBe('intent/v1:{"amount_cents":20000,"currency":"USD","recipient":"acme-991","reference":"A-991"}');
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    expect(Buffer.from(digest).toString("hex")).toBe(HASH);
  });

  it("sign to the same signature the desk verifies", async () => {
    const key = await crypto.subtle.importKey("pkcs8", Buffer.from(SEED_PKCS8, "hex"), { name: "Ed25519" }, false, ["sign"]);
    const signature = await crypto.subtle.sign({ name: "Ed25519" }, key, intentBytes(ACME));
    expect(toBase64(signature)).toBe(INTENT_SIGNATURE);
  });

  it.each([
    ["zero amount", { amount_cents: 0 }],
    ["fractional amount", { amount_cents: 200.5 }],
    ["a space", { recipient: "acme 991" }],
    ["non-ASCII", { reference: "A-991é" }],
    ["empty currency", { currency: "" }],
  ])("refuse %s", (_name, patch) => {
    expect(() => intentBytes({ ...ACME, ...patch })).toThrow("intent: malformed");
  });
});

describe("bank statement", () => {
  it("bytes are byte-identical to the bank's coop/v1 bytes", () => {
    expect(decode(stateBytes(STATE))).toBe(
      'coop/v1:{"balance_cents":50000,"currency":"USD","expires_at":1800001300,"issued_at":1800001000,' +
        `"nonce":"${HASH}","statement":"funds-sufficient","subject":"checking-881"}`,
    );
  });

  it("signed by the desk's bank verifies in the browser", async () => {
    expect(await verifyState(STATE, SEED_PUBLIC, HASH, 1800001100)).toBe("ok: cooperative");
  });

  it.each([
    ["a changed balance", { balance_cents: 90000 }, 1800001100, HASH, "bad-signature: state signature invalid"],
    ["a forged signature", { signature: toBase64(fromBase64(STATE.signature).reverse()) }, 1800001100, HASH, "bad-signature: state signature invalid"],
    ["another intent", {}, 1800001100, "b".repeat(64), "state: not bound to this intent"],
    ["an expired statement", {}, 1800001301, HASH, "stale: state expired"],
    ["a statement from the future", {}, 1800000999, HASH, "premature: state issued in future"],
  ])("refuses %s", async (_name, patch, now, hash, reason) => {
    expect(await verifyState({ ...STATE, ...patch }, SEED_PUBLIC, hash, now)).toBe(reason);
  });
});

it("formats integer cents", () => {
  expect([formatAmount(20000, "USD"), formatAmount(7, "USD")]).toEqual(["200.00 USD", "0.07 USD"]);
});
