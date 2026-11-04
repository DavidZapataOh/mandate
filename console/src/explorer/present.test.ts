import { describe, expect, it } from "vitest";
import { AUDITOR, RECEIPT } from "./__fixtures__/receipts";
import { presentation } from "./present";
import { parseReceipt } from "./receipt";
import { readDisclosure } from "./sdjwt";

const full = parseReceipt(JSON.parse(RECEIPT));
const names = (sd: string) => sd.split("~").slice(1, -1).map((d) => readDisclosure(d)?.name);

describe("presentation matches swarm/receipt.py present", () => {
  it("drops every personal field for the auditor copy", () => {
    expect(JSON.stringify(presentation(full, new Set()))).toBe(AUDITOR);
  });
  it("keeps only the amount when only the amount is revealed", () => {
    expect(names(presentation(full, new Set(["amount"])).sd)).toEqual(["amount_cents", "currency"]);
  });
  it("reveals the targets, the action salt and the consent signature only with every field group", () => {
    expect(names(presentation(full, new Set(["amount", "payee"])).sd)).toEqual(["amount_cents", "currency", "recipient"]);
    expect(names(presentation(full, new Set(["account"])).sd)).toEqual(["source"]);
    expect(names(presentation(full, new Set(["holder"])).sd)).toEqual(["holder_key", "key_signature"]);
    expect(names(presentation(full, new Set(["amount", "payee", "account", "reference"])).sd)).toEqual([
      "targets", "action_salt", "amount_cents", "currency", "recipient", "reference", "source", "signature",
    ]);
    expect(JSON.stringify(presentation(full, new Set(["amount", "payee", "account", "reference", "holder"])))).toBe(RECEIPT);
  });
});
