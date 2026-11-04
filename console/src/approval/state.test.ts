import { describe, expect, it } from "vitest";
import { ATTACK } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { checked, desk, FIELDS } from "./__fixtures__/desk";
import { expiredAt, focusQuote, outcomeFor } from "./state";

const EVIL = { ...FIELDS, recipient: "evil-666" };
const ATTACK_LINE = parseLine(ATTACK);
const refusal = { reason: "consent: bad signature" };

describe("outcomeFor", () => {
  it.each([
    ["only the quote", [desk(1, "quote", "quoted")], "waiting", null, null],
    [
      "a refused signature",
      [desk(1, "quote", "quoted"), desk(2, "approve", "denied", refusal)],
      "refused",
      "consent: bad signature",
      null,
    ],
    [
      "a refused signature, then a good one",
      [
        desk(1, "quote", "quoted"),
        desk(2, "approve", "denied", refusal),
        desk(3, "approve", "approved"),
      ],
      "approved",
      null,
      null,
    ],
    [
      "an approval past its deadline",
      [desk(1, "quote", "quoted"), desk(2, "approve", "expired")],
      "expired",
      null,
      null,
    ],
    [
      "a paid confirm",
      [
        desk(1, "quote", "quoted"),
        desk(2, "approve", "approved"),
        desk(3, "confirm", "confirmed", { payment_id: "pay:000001", reason: "ok: executed" }),
      ],
      "paid",
      "ok: executed",
      "pay:000001",
    ],
    [
      "a confirm the gate denied",
      [
        desk(1, "quote", "quoted"),
        desk(2, "approve", "approved"),
        desk(3, "confirm", "denied", { reason: "consent: expired" }),
      ],
      "denied",
      "consent: expired",
      null,
    ],
  ] as const)("reads %s", (_name, lines, phase, reason, paymentId) => {
    const out = outcomeFor(lines, "q:000001");
    expect([out.phase, out.reason, out.paymentId]).toEqual([phase, reason, paymentId]);
  });

  it("keeps the consent the gate checked on confirm", () => {
    const lines = [desk(3, "confirm", "confirmed", {}, checked(EVIL))];
    expect(outcomeFor(lines, "q:000001").gateConsent).toEqual(EVIL);
  });

  it("ignores other quotes and other sources", () => {
    const lines = [
      desk(1, "quote", "quoted"),
      desk(2, "approve", "approved", { quote_id: "q:000002" }),
      ATTACK_LINE,
    ];
    expect(outcomeFor(lines, "q:000001").phase).toBe("waiting");
  });
});

describe("focusQuote", () => {
  it("follows the newest desk line that names a quote", () => {
    const lines = [
      desk(1, "quote", "quoted", { quote_id: "q:000002" }),
      desk(2, "approve", "approved", { quote_id: "q:000001" }),
      desk(3, "quote", "denied", { quote_id: null, reason: "consent: malformed" }),
    ];
    expect(focusQuote(lines, ["q:000002"])).toBe("q:000001");
  });

  it("falls back to the newest pending quote, then to nothing", () => {
    expect(focusQuote([ATTACK_LINE], ["q:000003", "q:000004"])).toBe("q:000004");
    expect(focusQuote([], [])).toBeNull();
  });
});

describe("expiredAt", () => {
  it.each([
    [1800001600 * 1000, false],
    [1800001600 * 1000 + 999, false],
    [1800001601 * 1000, true],
  ])("at %i ms is %s", (nowMs, expired) => {
    expect(expiredAt(FIELDS, nowMs)).toBe(expired);
  });
});
