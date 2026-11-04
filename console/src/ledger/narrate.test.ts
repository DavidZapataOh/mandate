import { describe, expect, it } from "vitest";
import { ATTACK, CONFIRM, patch } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { formatLatency } from "../shared/format";
import { forensicText, gameText } from "./narrate";

const confirmEvent = JSON.parse(CONFIRM).event;
const hook = (verdict: string) =>
  patch(
    ATTACK,
    {
      source: "hook",
      forensic: null,
      event: { ...confirmEvent, verdict, reason: "scope: target outside delegation" },
      subject: { agent: "child-1", tool: "edit_file", targets: [], tool_use_id: null },
    },
  );
const bill = (verdict: string) =>
  patch(CONFIRM, {
    source: "bill",
    event: { ...confirmEvent, verdict, reason: "recipient differs from intent" },
    subject: {
      proposal_call_id: "call_1",
      summary: "Pay 200.00 USD to acme-991 (ref A-991) from checking-881",
      confirmation: null,
      report_error: null,
    },
  });

describe("gameText", () => {
  it.each([
    [
      "intent signed",
      patch(CONFIRM, { event: null }, { step: "intent", status: "signed", quote_id: null, payment_id: null, reason: null }),
      "Holder signed intent: MANDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) from checking-881",
    ],
    [
      "intent refused",
      patch(CONFIRM, { event: null }, { step: "intent", status: "denied", quote_id: null, payment_id: null, reason: "intent: bad signature" }),
      "Intent refused: intent: bad signature",
    ],
    [
      "bank balance proven",
      patch(CONFIRM, { event: null, forensic: null }, {
        step: "intent", status: "proven", quote_id: null, payment_id: null, reason: null,
        summary: "Pay 200.00 USD to acme-991 (ref A-991) from checking-881",
      }),
      "Bank balance proven (zkTLS): Pay 200.00 USD to acme-991 (ref A-991) from checking-881",
    ],
    [
      "funds proof refused",
      patch(CONFIRM, { event: null, forensic: null }, {
        step: "intent", status: "denied", quote_id: null, payment_id: null,
        reason: "zktls: stale session",
      }),
      "Funds proof refused: zktls: stale session",
    ],
    [
      "paid",
      CONFIRM,
      "Paid ✓ MANDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) from checking-881 in 61µs",
    ],
    [
      "quoted",
      patch(CONFIRM, { event: null }, { step: "quote", status: "quoted", summary: "Pay 1.00 USD to x (ref r) from s" }),
      "Quote q:000001: Pay 1.00 USD to x (ref r) from s",
    ],
    [
      "quote refused",
      patch(CONFIRM, { event: null }, { step: "quote", status: "denied", quote_id: null, reason: "consent: malformed" }),
      "Quote refused: consent: malformed",
    ],
    [
      "approved",
      patch(CONFIRM, { event: null }, { step: "approve", status: "approved", reason: null }),
      "Holder approved q:000001",
    ],
    [
      "approval refused",
      patch(CONFIRM, { event: null }, { step: "approve", status: "denied", reason: "consent: bad signature" }),
      "Approval of q:000001 refused: consent: bad signature",
    ],
    [
      "payment denied",
      patch(CONFIRM, {}, { status: "denied", payment_id: null, reason: "consent: expired" }),
      "Payment q:000001 denied: consent: expired",
    ],
    ["blocked attack", ATTACK, "Blocked payee swap at model->gate: recipient differs from intent"],
    [
      "unblocked attack",
      patch(ATTACK, {}, { blocked: false, reason: "ok: executed" }),
      "NOT BLOCKED: payee swap at model->gate: ok: executed",
    ],
    ["hook allowed", hook("MET"), "child-1 ran edit_file"],
    ["hook denied", hook("NOT_MET"), "child-1 denied edit_file: scope: target outside delegation"],
    ["bill paid", bill("MET"), "Bill paid ✓ Pay 200.00 USD to acme-991 (ref A-991) from checking-881"],
    [
      "bill denied",
      bill("NOT_MET"),
      "Bill denied: Pay 200.00 USD to acme-991 (ref A-991) from checking-881: recipient differs from intent",
    ],
  ])("narrates %s", (_name, text, want) => {
    expect(gameText(parseLine(text))).toBe(want);
  });
});

describe("forensicText", () => {
  it("shows seq, source, verdict, hash prefix and reason", () => {
    expect(forensicText(parseLine(ATTACK))).toBe(
      "#4 attack NOT_MET 89f0357807b9 recipient differs from intent",
    );
    expect(forensicText(parseLine(patch(ATTACK, { event: null, forensic: null })))).toBe(
      "#4 attack - - recipient differs from intent",
    );
  });
});

describe("formatLatency", () => {
  it.each([
    [61, "61µs"],
    [999.4, "999µs"],
    [1000, "1.0ms"],
    [1530, "1.5ms"],
  ])("%d us", (us, want) => {
    expect(formatLatency(us)).toBe(want);
  });
});
