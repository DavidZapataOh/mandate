import { expect, test } from "vitest";
import type { ConsoleLine } from "../wire/types";
import { cueFor } from "./cues";

const SUMMARY = "Pay 200.00 USD to acme-991 (ref A-991) from checking-881";

function intentLine(status: string, reason: string | null): ConsoleLine {
  return {
    v: 3, seq: 1, source: "desk", event: null, meta: null, forensic: null,
    subject: { step: "intent", quote_id: null, status, summary: SUMMARY, payment_id: null, reason },
  };
}

test("the holder's signed intent shows at the booth as the holder's note", () => {
  const c = cueFor(intentLine("signed", null));
  expect([c.actor, c.tag, c.route, c.seal, c.outcome, c.bank, c.bubble, c.alert]).toEqual([
    "holder", "holder", "none", null, "note", false, `Holder signed: ${SUMMARY}`, null,
  ]);
});

test("a refused intent is the holder's denial, not the agent's", () => {
  const c = cueFor(intentLine("denied", "intent: bad signature"));
  expect([c.actor, c.route, c.seal, c.outcome, c.alert]).toEqual(["holder", "none", "deny", "deny", "denied · intent: bad signature"]);
});
