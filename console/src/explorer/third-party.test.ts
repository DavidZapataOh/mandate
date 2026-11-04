import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import OTS from "./__fixtures__/ots.json" with { type: "json" };
import { disclosureText } from "./__fixtures__/receipts";
import { fromBase64 } from "./bytes";
import { carries, receiptHash } from "./lookup";
import { parseReceipt } from "./receipt";
import { readDisclosure } from "./sdjwt";
import { STEPS, verdictOf, verifyReceipt, type StepResult, type Trust } from "./verify";

// Receipts a live desk issued minutes ago, written by e2e/test_third_party.py.
const FILE = process.env.MANDATE_CASE;
type Copy = { sd: string; payment_id: string; registry: { seal: { root: string }; entry: { body: string } } };
interface Keys {
  gate_key: string;
  holder_keys: string[];
}
interface Case {
  keys: Keys;
  holder: Copy;
  auditor: Copy;
  other_desk: Copy;
  // The digest the desk's own code says this desk stamps for the holder copy's seal.
  anchor_digest: string;
  sandbox: Copy;
  sandbox_keys: Keys;
}
const CASE: Case | null = FILE ? (JSON.parse(readFileSync(FILE, "utf8")) as Case) : null;

const trust = (keys: Keys): Trust => ({ gateKey: fromBase64(keys.gate_key), holderKeys: keys.holder_keys.map(fromBase64) });
const copy = (r: Copy): Copy => structuredClone(r);
const parts = (r: Copy) => {
  const [token, ...rest] = r.sd.split("~");
  return { token: token!, disclosures: rest.slice(0, -1) };
};
/** The copy with one disclosed value swapped for one the gate never signed. */
const swapped = (r: Copy, name: string, value: unknown): Copy => {
  const { token, disclosures } = parts(r);
  const out = disclosures.map((d) => (readDisclosure(d)?.name === name ? disclosureText(name, value) : d));
  return { ...copy(r), sd: [token, ...out, ""].join("~") };
};
/** The copy with a disclosure the gate never signed appended. */
const added = (r: Copy, name: string, value: unknown): Copy => {
  const { token, disclosures } = parts(r);
  return { ...copy(r), sd: [token, ...disclosures, disclosureText(name, value), ""].join("~") };
};
const edited = (r: Copy, edit: (c: Copy) => void): Copy => {
  const c = copy(r);
  edit(c);
  return c;
};
const anchored = (r: Copy, ots: string, bitcoin: { height: number; header: string } | null): Copy =>
  ({ ...copy(r), public_anchor: { v: 1, ots, bitcoin } }) as Copy;
const at = (results: StepResult[], step: string) => results.find((r) => r.step === step);
const NO_ANCHOR = "No public timestamp in this receipt: the desk has not stamped its seal";

describe.skipIf(CASE === null)("a third party holding only a receipt and the published keys", () => {
  const live = CASE!;
  const own = () => `${live.anchor_digest.slice(0, 12)}…`;

  it("verifies the holder copy offline, every step but the unstamped anchor passing", async () => {
    const results = await verifyReceipt(live.holder, trust(live.keys));
    expect(results.map((r) => r.step)).toEqual([...STEPS]);
    expect(results.map((r) => r.status)).toEqual(STEPS.map((s) => (s === "Public anchor" ? "unchecked" : "pass")));
    expect(at(results, "Public anchor")?.detail).toBe(NO_ANCHOR);
    expect(at(results, "Bank transfer")?.detail).toBe(
      "SIMULATED ledger payment pay:000001, requested under this certificate; no bank holds it",
    );
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED",
      text: "Every link of the chain verified in this browser; no public timestamp yet",
    });
  });

  it("verifies the auditor copy without the personal fields", async () => {
    const results = await verifyReceipt(live.auditor, trust(live.keys));
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED, FIELDS WITHHELD",
      text: "Every disclosed link verified in this browser; 2 checks need fields the holder withheld; no public timestamp yet",
    });
  });

  it("names the sandbox transfer a served sandbox desk paid, without claiming the bank holds it", async () => {
    const results = await verifyReceipt(live.sandbox, trust(live.sandbox_keys));
    expect(at(results, "Bank transfer")).toEqual({
      step: "Bank transfer",
      status: "pass",
      detail:
        "SANDBOX transfer sandbox_account_transfer_4nicrwgr1kludye5vcc1 at increase, requested under this certificate; the gate signs this claim, and the id is checkable in the Increase sandbox dashboard of the account that holds the key",
    });
  });

  it.each([
    ["another desk's receipt", () => live.other_desk, "Gate certificate", () => "Not signed by the gate key (bad-signature: eddsa mismatch)"],
    ["a bigger amount", () => swapped(live.holder, "amount_cents", 2000000), "Receipt disclosures",
      () => "Disclosures do not verify (sd-jwt: disclosure not referenced)"],
    ["another payee", () => swapped(live.holder, "recipient", "evil-666"), "Receipt disclosures",
      () => "Disclosures do not verify (sd-jwt: disclosure not referenced)"],
    ["a payee added to the auditor copy", () => added(live.auditor, "recipient", "evil-666"), "Receipt disclosures",
      () => "Disclosures do not verify (sd-jwt: disclosure not referenced)"],
    ["another payment id", () => ({ ...copy(live.holder), payment_id: "pay:000002" }), "Receipt disclosures",
      () => "Disclosures are for pay:000001, not pay:000002"],
    ["another registry entry", () => edited(live.holder, (c) => {
      c.registry.entry.body = c.registry.entry.body.replace("pay:000001", "pay:000002");
    }), "Registry inclusion", () => "Registry entry is for pay:000002, not pay:000001"],
    ["another seal root", () => edited(live.holder, (c) => {
      c.registry.seal.root = "00".repeat(32);
    }), "Registry inclusion", () => "Proof recomputes root 70566024e09c…, not the sealed 000000000000…"],
    ["a confirmed Bitcoin proof of another document", () =>
      anchored(live.holder, OTS.core29.upgraded, { height: 892418, header: OTS.core29.headers["892418"] }),
      "Public anchor", () => `Public anchor proof is for 94ec151f452a…, not this seal's anchor digest ${own()}`],
    // Every desk's first seal root is 70566024e09c…; the stamp must still name this desk.
    ["another desk's stamp of the same seal root", () => anchored(live.holder, OTS.golden.pending, null),
      "Public anchor", () => `Public anchor proof is for fe28838c6cdc…, not this seal's anchor digest ${own()}`],
  ])("fails %s at the step it breaks", async (_name, forge, step, detail) => {
    const results = await verifyReceipt(forge(), trust(live.keys));
    const failed = results.findIndex((r) => r.status === "fail");
    expect(results[failed]).toEqual({ step, status: "fail", detail: detail() });
    expect(results.slice(failed + 1).every((r) => r.status === "unchecked")).toBe(true);
    expect(verdictOf(results).label).toBe("NOT VERIFIED");
  });

  it("catches a hash-lookup answer that does not carry the pasted hash", async () => {
    const pasted = await receiptHash(live.holder.sd);
    expect(await carries(parseReceipt(live.auditor), pasted)).toBe(true);
    expect(await carries(parseReceipt(live.other_desk), pasted)).toBe(false);
  });
});
