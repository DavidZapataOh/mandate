import { describe, expect, it } from "vitest";
import {
  consentBytes,
  consentHash,
  formatAmount,
  groupHex,
  readConsent,
  utcTime,
} from "./consent";

const GOLDEN =
  'consent/v1:{"amount_cents":20000,"currency":"USD","expires_at":1800001600,' +
  '"nonce":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0","recipient":"acme-991",' +
  '"reference":"A-991","source":"checking-881"}';
const FIELDS = {
  amount_cents: 20000,
  currency: "USD",
  expires_at: 1800001600,
  nonce: "c0".repeat(16),
  recipient: "acme-991",
  reference: "A-991",
  source: "checking-881",
};
const HASH = "a3a19e2b9de9b03342451a42d2fdbc06d4281d50f9ba2785362ba8db2b024ac7";

describe("consent bytes", () => {
  it("match the gate golden byte for byte", () => {
    expect(new TextDecoder().decode(consentBytes(FIELDS))).toBe(GOLDEN);
  });

  it("ignore the order the fields arrived in", () => {
    const reversed = Object.fromEntries(Object.entries(FIELDS).reverse());
    const shuffled = readConsent(reversed);
    expect(new TextDecoder().decode(consentBytes(shuffled))).toBe(GOLDEN);
  });

  it("hash to the gate's sha256", async () => {
    expect(await consentHash(FIELDS)).toBe(HASH);
  });

  it("have no hash without WebCrypto", async () => {
    expect(await consentHash(FIELDS, null)).toBeNull();
  });
});

describe("readConsent", () => {
  it("keeps the seven fields", () => {
    expect(readConsent({ ...FIELDS })).toEqual(FIELDS);
  });

  it.each([
    ["null", null],
    ["an array", [FIELDS]],
    ["a missing field", { ...FIELDS, nonce: undefined }],
    ["an extra field", { ...FIELDS, summary: "Pay 1.00 USD" }],
    ["a non-ASCII payee", { ...FIELDS, recipient: "acmé-991" }],
    ["a payee with a space", { ...FIELDS, recipient: "acme 991" }],
    ["an empty reference", { ...FIELDS, reference: "" }],
    ["a zero amount", { ...FIELDS, amount_cents: 0 }],
    ["a fractional amount", { ...FIELDS, amount_cents: 200.5 }],
    ["an amount as text", { ...FIELDS, amount_cents: "20000" }],
    ["a negative expiry", { ...FIELDS, expires_at: -1 }],
  ])("refuses %s", (_name, value) => {
    expect(() => readConsent(value)).toThrow("approval: malformed consent");
  });
});

describe("display helpers", () => {
  it("group a digest in eights", () => {
    expect(groupHex(HASH)).toBe(
      "a3a19e2b 9de9b033 42451a42 d2fdbc06 d4281d50 f9ba2785 362ba8db 2b024ac7",
    );
  });

  it.each([
    [20000, "USD", "200.00 USD"],
    [5, "EUR", "0.05 EUR"],
    [123456789, "USD", "1234567.89 USD"],
  ])("formats %i %s as %s", (cents, currency, shown) => {
    expect(formatAmount(cents, currency)).toBe(shown);
  });

  it("writes unix seconds as UTC", () => {
    expect(utcTime(1800001600)).toBe("2027-01-15 08:26:40 UTC");
  });
});
