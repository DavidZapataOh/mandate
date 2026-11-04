import { describe, expect, it } from "vitest";
import { concat, fromBase64, fromHex, toBase64 } from "./bytes";
import {
  AUDITOR,
  CONSENT,
  CONSENT_KEY,
  forge,
  GATE_KEY,
  HOLDER_KEY,
  RECEIPT,
  RECEIPT_COOP,
  RECEIPT_ZKTLS,
  regate,
  reissue,
  resign,
  SANDBOX_RECEIPT,
  seedPublicKey,
  seedSign,
  tamper,
} from "./__fixtures__/receipts";
import OTS from "./__fixtures__/ots.json" with { type: "json" };
import { keyBytes } from "./canon";
import { anchorDigest, consentBytes } from "./chain";
import { readDisclosure } from "./sdjwt";
import { parseDisclosed, parseReceipt, ReceiptError } from "./receipt";
import { disclosedOf, GROUPS, STEPS, verdictOf, verifyCertificate, verifyReceipt, type StepResult, type Trust } from "./verify";

const TRUST: Trust = {
  gateKey: fromBase64(GATE_KEY),
  holderKeys: [fromBase64(HOLDER_KEY)],
};
const statuses = async (text: string, trust: Trust = TRUST) =>
  (await verifyReceipt(JSON.parse(text), trust)).map((r) => `${r.step}: ${r.status}`);
const failed = async (text: string, trust: Trust = TRUST) =>
  (await verifyReceipt(JSON.parse(text), trust)).find((r) => r.status === "fail");
const chain = (results: StepResult[]) => results.filter((r) => r.step !== "Public anchor");

describe("verifyReceipt", () => {
  it.each([
    [{ v: 2, ots: "AA==", bitcoin: null }, "receipt: public_anchor.v malformed"],
    [{ v: 1, ots: "not base64!", bitcoin: null }, "receipt: public_anchor.ots malformed"],
    [{ v: 1, ots: "AA==", bitcoin: { height: 1, header: "00" } }, "receipt: public_anchor.bitcoin.header malformed"],
    [{ v: 1, ots: "AA==", bitcoin: null, extra: 1 }, "receipt: public_anchor malformed"],
  ])("refuses a public anchor block of the wrong shape %#", (anchor, message) => {
    expect(() => parseReceipt(JSON.parse(tamper("public_anchor", anchor)))).toThrow(message);
  });

  it("reads a receipt without a public anchor as null and refuses one missing the key", () => {
    expect(parseReceipt(JSON.parse(RECEIPT)).public_anchor).toBeNull();
    const { public_anchor: _, ...older } = JSON.parse(RECEIPT);
    expect(() => parseReceipt(older)).toThrow("receipt: public_anchor malformed");
  });

  it("passes every step of a receipt the desk issued", async () => {
    const results = await verifyReceipt(JSON.parse(RECEIPT), TRUST);
    expect(results.map((r) => r.step)).toEqual([...STEPS]);
    expect(chain(results).every((r) => r.status === "pass")).toBe(true);
    expect(results.map((r) => r.detail)).toEqual([
      "Receipt for pay:000001",
      "EdDSA signature verifies with gate key iojj3XQJ8ZX9…",
      "Signed by the gate key; every field disclosed",
      "HMAC-SHA256 of the canonical bytes under the disclosed salt is the certified hash 52e9b189b7db…",
      "Policy desk v1: MET (rule pay-with-consent, reported by the desk, not signed)",
      "Signed by a one-time key the paired holder key certified: 20000 USD cents to acme-991 (ref A-991)",
      "Entry 1 of 1 recomputes the sealed root 70566024e09c…",
      "Seal anch:000001 over entries 1–1 verifies",
      "No public timestamp in this receipt: the desk has not stamped its seal",
      "No model reasoning: the certificate commits to an empty chain",
      "SIMULATED ledger payment pay:000001, requested under this certificate; no bank holds it",
      "No funds evidence: this payment was not bound to a holder intent",
    ]);
  });

  it.each([
    ["policy.policy_id", "payments", "Policy", "Certificate names policy desk v1, not payments v1"],
    ["payment_id", "pay:000002", "Receipt disclosures", "Disclosures are for pay:000001, not pay:000002"],
    ["registry.entry.body", '{"payment_id":"pay:000002","quote_id":"q:000001","reason":"ok: executed","status":"confirmed"}',
      "Registry inclusion", "Registry entry is for pay:000002, not pay:000001"],
    ["registry.seal.ts", 1800009999, "Registry seal", "Seal anch:000001 is not signed by the gate key"],
    ["reasoning", { v: 1, model: "muse-spark-1.3", response_id: "resp_x", blobs: ["b"] }, "Reasoning anchor",
      "Anchor digest adb17ee586c9… differs from the certified commitment"],
  ])("a receipt with %s changed fails at the step that checks it", async (path, value, step, detail) => {
    const results = await verifyReceipt(JSON.parse(tamper(path, value)), TRUST);
    const at = results.findIndex((r) => r.status === "fail");
    expect(results[at]).toEqual({ step, status: "fail", detail });
    expect(chain(results.slice(0, at)).every((r) => r.status === "pass")).toBe(true);
    expect(results.slice(at + 1).map((r) => r.status)).toEqual(results.slice(at + 1).map(() => "unchecked"));
  });

  it.each([
    ["amount_cents", 2000000],
    ["recipient", "evil-666"],
  ])("a %s disclosure the gate never signed fails at the disclosures", async (name, value) => {
    expect(await statuses(forge(name, value))).toEqual([
      "Receipt format: pass", "Gate certificate: pass", "Receipt disclosures: fail",
      ...STEPS.slice(3).map((s) => `${s}: unchecked`),
    ]);
    expect((await failed(forge(name, value)))?.detail).toBe("Disclosures do not verify (sd-jwt: disclosure not referenced)");
  });

  it.each([
    ["targets", ["amount:USD:20000", "from:checking-881", "ref:A-991", "to:evil-666"], "Canonical action",
      "Action hash 4694a2f9d3a9… differs from the certified 52e9b189b7db…"],
    ["action_salt", "02".repeat(32), "Canonical action", "Action hash 96b570044c21… differs from the certified 52e9b189b7db…"],
    ["amount_cents", 2000000, "Holder consent", "Holder signature does not verify over the consent bytes"],
    ["recipient", "acme 991", "Holder consent", "Consent is malformed"],
    ["holder_key", GATE_KEY, "Holder consent", "The holder key did not certify the consent key"],
  ])("a gate-signed %s that contradicts the certificate or the holder fails where it is checked", async (name, value, step, detail) => {
    const results = await verifyReceipt(JSON.parse(await regate(name, value)), TRUST);
    const at = results.findIndex((r) => r.status === "fail");
    expect(results[at]).toEqual({ step, status: "fail", detail });
    expect(results.slice(0, at).every((r) => r.status === "pass")).toBe(true);
  });

  it("verifies the auditor copy without the personal fields", async () => {
    const results = await verifyReceipt(JSON.parse(AUDITOR), TRUST);
    expect(results.map((r) => `${r.step}: ${r.status}`)).toEqual([
      "Receipt format: pass", "Gate certificate: pass", "Receipt disclosures: pass", "Canonical action: withheld",
      "Policy: pass", "Holder consent: withheld", "Registry inclusion: pass", "Registry seal: pass", "Public anchor: unchecked",
      "Reasoning anchor: pass", "Bank transfer: pass", "Funds proof: pass",
    ]);
    expect(results[2]?.detail).toBe("Signed by the gate key; withheld by the holder: amount, payee, account, reference, holder");
    expect(results[3]?.detail).toBe("Withheld: the action's targets and salt were not disclosed; the certificate still fixes its salted hash");
    expect(results[5]?.detail).toBe("Withheld: the holder's signed fields were not all disclosed");
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED, FIELDS WITHHELD",
      text: "Every disclosed link verified in this browser; 2 checks need fields the holder withheld; no public timestamp yet",
    });
  });

  it("verifies a holder copy without its holder group and says the identity is withheld", async () => {
    const copy = JSON.parse(RECEIPT);
    const hidden = ["holder_key", "key_signature"];
    copy.sd = copy.sd.split("~").filter((d: string) => !hidden.includes(readDisclosure(d)?.name ?? "")).join("~");
    const results = await verifyReceipt(copy, TRUST);
    expect(chain(results).every((r) => r.status === "pass")).toBe(true);
    expect(results[2]?.detail).toBe("Signed by the gate key; disclosed: amount, payee, account, reference; withheld: holder");
    expect(results[5]?.detail).toBe(
      "Signed by a one-time key; holder identity withheld (the gate checked its certificate): 20000 USD cents to acme-991 (ref A-991)",
    );
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED",
      text: "Every link of the chain verified in this browser; the holder's identity rests on the gate; no public timestamp yet",
    });
  });

  it("says every link verified when the holder group is disclosed too", async () => {
    expect(verdictOf(await verifyReceipt(JSON.parse(RECEIPT), TRUST))).toEqual({
      label: "VERIFIED",
      text: "Every link of the chain verified in this browser; no public timestamp yet",
    });
  });

  it("never presents the unsigned rule id as verified", async () => {
    const results = await verifyReceipt(JSON.parse(tamper("policy.rule_id", "any-rule")), TRUST);
    expect(results[4]).toEqual({
      step: "Policy",
      status: "pass",
      detail: "Policy desk v1: MET (rule any-rule, reported by the desk, not signed)",
    });
  });

  it("fails at the certificate under a key the auditor did not pin", async () => {
    expect(await failed(RECEIPT, { ...TRUST, gateKey: fromBase64(HOLDER_KEY) })).toEqual({
      step: "Gate certificate",
      status: "fail",
      detail: "Not signed by the gate key (bad-signature: eddsa mismatch)",
    });
  });

  it("fails at the consent when the desk trusts another holder", async () => {
    expect(await failed(RECEIPT, { ...TRUST, holderKeys: [fromBase64(GATE_KEY)] })).toMatchObject({
      step: "Holder consent",
      detail: "Signed by a key this desk does not trust",
    });
  });

  it("names the malformed field and checks nothing else", async () => {
    expect(await statuses(tamper("registry.proof.siblings", "none"))).toEqual([
      "Receipt format: fail",
      ...STEPS.slice(1).map((s) => `${s}: unchecked`),
    ]);
    expect((await failed(tamper("registry.proof.siblings", "none")))?.detail).toBe(
      "receipt: registry.proof.siblings malformed",
    );
    expect((await failed(JSON.stringify({ ...JSON.parse(RECEIPT), extra: 1 })))?.detail).toBe("receipt: malformed");
  });
});

const bank = (change: Record<string, unknown> | null) => (p: Record<string, unknown>) => {
  p.bank = change === null ? null : { ...(p.bank as object), ...change };
};

describe("bank transfer step", () => {
  it.each([
    [null, "Receipt names no bank transfer"],
    [{ idempotency_key: "mandate-cert-other" }, "Bank transfer was not requested under this certificate"],
    [{ transfer_id: "pay:000002" }, "Bank transfer pay:000002 is not the sealed payment pay:000001"],
    [{ status: "pending_approval" }, "Bank reports the transfer pending_approval, not complete"],
  ])("a gate-signed bank block %j fails at the bank step", async (change, detail) => {
    expect(await failed(await resign(bank(change)))).toEqual({ step: "Bank transfer", status: "fail", detail });
  });

  it("names a sandbox transfer and where it can be checked, without claiming it was", async () => {
    const results = await verifyReceipt(JSON.parse(SANDBOX_RECEIPT), TRUST);
    expect(results.map((r) => r.status)).toEqual(STEPS.map((s) => (s === "Public anchor" ? "unchecked" : "pass")));
    expect(results.find((r) => r.step === "Bank transfer")).toEqual({
      step: "Bank transfer",
      status: "pass",
      detail:
        "SANDBOX transfer account_transfer_t1 at increase, requested under this certificate; the gate signs this claim, and the id is checkable in the Increase sandbox dashboard of the account that holds the key",
    });
  });

  it.each([
    [{ provider: null }, "Sandbox transfer names provider null, not increase"],
    [{ provider: "acme-bank" }, "Sandbox transfer names provider acme-bank, not increase"],
    [{ transfer_id: "pay:000001" }, "Bank transfer pay:000001 is not an Increase transfer id"],
    [{ transfer_id: "account_transfer_" }, "Bank transfer account_transfer_ is not an Increase transfer id"],
    [{ transfer_id: "sandbox_account_transfer_a-b" }, "Bank transfer sandbox_account_transfer_a-b is not an Increase transfer id"],
    [{ transfer_id: `account_transfer_${"a".repeat(65)}` }, `Bank transfer account_transfer_${"a".repeat(65)} is not an Increase transfer id`],
  ])("a sandbox claim %j that is not an Increase transfer fails", async (change, detail) => {
    expect(await failed(await resign(bank(change), SANDBOX_RECEIPT))).toEqual({ step: "Bank transfer", status: "fail", detail });
  });

  it("a simulated payment relabelled sandbox by the gate key fails at the bank step", async () => {
    expect(await failed(await resign(bank({ rail: "sandbox", provider: "increase" })))).toEqual({
      step: "Bank transfer",
      status: "fail",
      detail: "Bank transfer pay:000001 is not an Increase transfer id",
    });
  });

  it("refuses a rail it does not know", async () => {
    expect((await failed(await resign(bank({ rail: "real" }))))?.detail).toBe("receipt: sd.bank.rail malformed");
  });

  it("refuses a gate-signed payload that leaves the bank claim out", async () => {
    const omitted = await resign((p) => {
      delete p.bank;
    });
    expect(await failed(omitted)).toEqual({ step: "Receipt disclosures", status: "fail", detail: "receipt: sd.bank malformed" });
  });

  it.each([
    [{ provider: 1 }, "receipt: sd.bank.provider malformed"],
    [{ idempotency_key: 2 }, "receipt: sd.bank.idempotency_key malformed"],
    [{ transfer_id: null }, "receipt: sd.bank.transfer_id malformed"],
    [{ extra: 1 }, "receipt: sd.bank malformed"],
  ])("refuses a malformed gate-signed bank block %j at the disclosures", async (change, detail) => {
    expect(await failed(await resign(bank(change)))).toEqual({ step: "Receipt disclosures", status: "fail", detail });
  });

  it("refuses a rail label changed without the gate key", async () => {
    const r = JSON.parse(RECEIPT);
    const [token, ...rest] = r.sd.split("~");
    const [h, p, sig] = token.split(".");
    const payload = JSON.parse(new TextDecoder().decode(fromBase64(p.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (p.length % 4)) % 4))));
    payload.bank.rail = "sandbox";
    const edited = btoa(JSON.stringify(payload)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    r.sd = [`${h}.${edited}.${sig}`, ...rest].join("~");
    expect((await failed(JSON.stringify(r)))?.detail).toBe("Disclosures do not verify (sd-jwt: bad signature)");
  });
});

describe("verifyCertificate", () => {
  const token = JSON.parse(RECEIPT).certificate;

  it("checks only the signature and asks for the receipt", async () => {
    const results = await verifyCertificate(token, TRUST);
    expect(results.map((r) => r.status)).toEqual([
      "unchecked", "pass", "unchecked", "unchecked", "unchecked", "unchecked", "unchecked", "unchecked", "unchecked",
      "unchecked", "unchecked", "unchecked",
    ]);
    expect(verdictOf(results)).toEqual({
      label: "INCOMPLETE",
      text: "The certificate verifies; paste the full receipt to check the chain",
    });
  });

  it("fails a certificate signed by another key", async () => {
    const results = await verifyCertificate(token, { ...TRUST, gateKey: fromBase64(HOLDER_KEY) });
    expect(verdictOf(results)).toEqual({
      label: "NOT VERIFIED",
      text: "Failed at Gate certificate: Not signed by the gate key (bad-signature: eddsa mismatch)",
    });
  });
});

const H18 = OTS.core29.headers["892418"];
const anchored = (ots: string, bitcoin: { height: number; header: string } | null = null, text = RECEIPT) =>
  tamper("public_anchor", { v: 1, ots, bitcoin }, text);
const anchorOf = (results: StepResult[]) => results.find((r) => r.step === "Public anchor");
const PENDING_DETAIL =
  "PENDING: submitted to 4 OpenTimestamps calendars (alice.btc.calendar.opentimestamps.org, " +
  "bob.btc.calendar.opentimestamps.org, btc.calendar.catallaxy.com, finney.calendar.eternitywall.com); " +
  "no Bitcoin block attests this seal yet";

// Hand-built proofs over the golden seal's anchor digest, for branches no recorded proof reaches.
const OTS_MAGIC = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294";
const UNKNOWN_TAG = "0102030405060708";
const varuint = (n: number) => {
  const out: number[] = [];
  do {
    out.push((n & 0x7f) | (n > 0x7f ? 0x80 : 0));
    n = Math.floor(n / 128);
  } while (n > 0);
  return new Uint8Array(out);
};
const varbytes = (b: Uint8Array) => concat(varuint(b.length), b);
const attestation = (tag: string, payload: Uint8Array) => concat(new Uint8Array([0]), fromHex(tag), varbytes(payload));
const pendingAt = (uri: string) => attestation("83dfe30d2ef90c8e", varbytes(new TextEncoder().encode(uri)));
const bitcoinAt = (height: number) => attestation("0588960d73d71901", varuint(height));
const goldenProof = (tree: Uint8Array) =>
  toBase64(concat(fromHex(OTS_MAGIC), new Uint8Array([1, 0x08]), fromHex(OTS.golden.digest), tree));

describe("public anchor step", () => {
  it("says a receipt carries no public timestamp without failing it", async () => {
    const results = await verifyReceipt(JSON.parse(RECEIPT), TRUST);
    expect(anchorOf(results)).toEqual({
      step: "Public anchor", status: "unchecked",
      detail: "No public timestamp in this receipt: the desk has not stamped its seal",
    });
    expect(results.map((r) => r.step).indexOf("Public anchor")).toBe(8);
  });

  it("shows a stamp the calendars hold as PENDING, never as a pass", async () => {
    const results = await verifyReceipt(JSON.parse(anchored(OTS.golden.pending)), TRUST);
    expect(anchorOf(results)).toEqual({ step: "Public anchor", status: "pending", detail: PENDING_DETAIL });
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED",
      text: "Every link of the chain verified in this browser; its Bitcoin timestamp is pending",
    });
  });

  it("keeps the auditor copy's label and names the pending timestamp", async () => {
    const results = await verifyReceipt(JSON.parse(anchored(OTS.golden.pending, null, AUDITOR)), TRUST);
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED, FIELDS WITHHELD",
      text: "Every disclosed link verified in this browser; 2 checks need fields the holder withheld; its Bitcoin timestamp is pending",
    });
  });

  it.each([
    [anchored(OTS.core29.upgraded, { height: 892418, header: H18 }), "Public anchor proof is for 94ec151f452a…, not this seal's anchor digest fe28838c6cdc…"],
    [anchored(OTS.core29.upgraded), "Public anchor proof is for 94ec151f452a…, not this seal's anchor digest fe28838c6cdc…"],
    [anchored(OTS.golden.pending, { height: 892418, header: H18 }), "Public anchor proof names no Bitcoin block 892418"],
    [anchored(btoa("nope")), "Public anchor proof is malformed (not an OpenTimestamps proof)"],
    [anchored(OTS.hello2015.proof), "Public anchor proof is malformed (unsupported operation 0x03)"],
  ])("fails a proof that does not anchor this seal %#", async (text, detail) => {
    const results = await verifyReceipt(JSON.parse(text), TRUST);
    expect(anchorOf(results)).toEqual({ step: "Public anchor", status: "fail", detail });
    expect(verdictOf(results).label).toBe("NOT VERIFIED");
    expect(results.slice(9).every((r) => r.status === "unchecked")).toBe(true);
  });

  it("fails a proof over this seal's anchor digest that attests nothing", async () => {
    const results = await verifyReceipt(JSON.parse(anchored(goldenProof(attestation(UNKNOWN_TAG, new Uint8Array(0))))), TRUST);
    expect(anchorOf(results)).toEqual({ step: "Public anchor", status: "fail", detail: "Public anchor proof attests nothing" });
  });

  it("names a calendar URI that does not parse as it is written", async () => {
    const results = await verifyReceipt(JSON.parse(anchored(goldenProof(pendingAt("calendar-without-scheme")))), TRUST);
    expect(anchorOf(results)).toEqual({
      step: "Public anchor", status: "pending",
      detail: "PENDING: submitted to 1 OpenTimestamps calendars (calendar-without-scheme); no Bitcoin block attests this seal yet",
    });
  });

  it("names the Bitcoin block a proof already holds beside its calendars", async () => {
    const tree = concat(new Uint8Array([0xff]), bitcoinAt(892418), pendingAt("https://alice.btc.calendar.opentimestamps.org"));
    const results = await verifyReceipt(JSON.parse(anchored(goldenProof(tree))), TRUST);
    expect(anchorOf(results)).toEqual({
      step: "Public anchor", status: "pending",
      detail: "PENDING: the proof names Bitcoin block 892418, but this receipt carries no block header to check it against",
    });
  });

  it("keeps a proof with a Bitcoin block but no header pending and names what is missing", async () => {
    const results = await verifyReceipt(JSON.parse(anchored(goldenProof(bitcoinAt(892418)))), TRUST);
    expect(anchorOf(results)).toEqual({
      step: "Public anchor", status: "pending",
      detail: "PENDING: the proof names Bitcoin block 892418, but this receipt carries no block header to check it against",
    });
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED",
      text: "Every link of the chain verified in this browser; its Bitcoin timestamp is pending",
    });
  });

  it("refuses a proof over the bare seal root", async () => {
    const results = await verifyReceipt(JSON.parse(anchored(OTS.bare.pending)), TRUST);
    expect(anchorOf(results)).toEqual({
      step: "Public anchor", status: "fail",
      detail: "Public anchor proof is for 70566024e09c…, not this seal's anchor digest fe28838c6cdc…",
    });
  });

  it("refuses a proof borrowed from another desk whose seal has the same root", async () => {
    // The golden seal's fields and root, signed by another gate key: the same root, another desk.
    expect(OTS.foreign.digest).not.toBe(OTS.golden.digest);
    const results = await verifyReceipt(JSON.parse(anchored(OTS.foreign.pending)), TRUST);
    expect(anchorOf(results)).toEqual({
      step: "Public anchor", status: "fail",
      detail: "Public anchor proof is for c46a611449cf…, not this seal's anchor digest fe28838c6cdc…",
    });
    expect(verdictOf(results).label).toBe("NOT VERIFIED");
  });

  it("derives the anchor digest from the gate key and the signed seal", async () => {
    const seal = parseReceipt(JSON.parse(RECEIPT)).registry.seal;
    expect(await anchorDigest(seal, TRUST.gateKey)).toBe("fe28838c6cdcfc365aef8d643ea05cd90abb7e58ffe7f60dfb57ea077fcf071a");
    expect(await anchorDigest(seal, fromBase64(OTS.foreign.gate_key))).not.toBe(OTS.golden.digest);
  });

  const CONFIRMED = { height: OTS.golden.bitcoin!.height, header: OTS.golden.bitcoin!.header };
  const flipped = (hex: string) => hex.slice(0, -2) + (parseInt(hex.slice(-2), 16) ^ 1).toString(16).padStart(2, "0");

  it("passes as CONFIRMED only when the proof reaches a header with real work", async () => {
    const results = await verifyReceipt(JSON.parse(anchored(OTS.golden.confirmed!, CONFIRMED)), TRUST);
    expect(anchorOf(results)).toEqual({
      step: "Public anchor",
      status: "pass",
      detail:
        "CONFIRMED: this seal is committed in Bitcoin block 974543 " +
        "(00000000000000000000f7813784860e3eb0202a11238f2848130e94889d94d6), mined 2026-11-04T15:50:08Z; " +
        "this browser checked the proof and the header's proof of work, not that the block is in the main chain: " +
        "look the block up at any Bitcoin explorer or run ots verify",
    });
    expect(verdictOf(results).text).toBe("Every link of the chain verified in this browser; its seal is timestamped in Bitcoin");
  });

  it.each([
    [{ ...CONFIRMED, header: flipped(CONFIRMED.header) }, "Bitcoin block 974543 header misses its proof-of-work target"],
    [{ ...CONFIRMED, header: OTS.hello2015.header }, "Bitcoin block 974543 header is below the work floor"],
    [{ ...CONFIRMED, header: OTS.core29.headers["892418"] }, "Bitcoin block 974543 header does not hold the proof's merkle root"],
  ])("fails the golden stamp beside a header that is not its block %#", async (bitcoin, detail) => {
    const results = await verifyReceipt(JSON.parse(anchored(OTS.golden.confirmed!, bitcoin)), TRUST);
    expect(anchorOf(results)).toEqual({ step: "Public anchor", status: "fail", detail });
  });
});

describe("verdictOf", () => {
  it("is VERIFIED only when all twelve steps ran and every chain step passed", async () => {
    expect(verdictOf(await verifyReceipt(JSON.parse(RECEIPT), TRUST)).label).toBe("VERIFIED");
    expect(verdictOf((await verifyReceipt(JSON.parse(RECEIPT), TRUST)).slice(0, 11)).label).toBe("INCOMPLETE");
  });

  it("notes when no holder list was published", async () => {
    const results = await verifyReceipt(JSON.parse(RECEIPT), { ...TRUST, holderKeys: null });
    expect(results[5]?.detail).toBe(
      "Signed by a one-time key the paired holder key certified: 20000 USD cents to acme-991 (ref A-991) (no published holder list to compare)",
    );
  });
});

// Hardening beyond the pinned copy: no input throws out of the chain, and nothing passes after a failure.
const without = (text: string, names: readonly string[]) => {
  const copy = JSON.parse(text);
  copy.sd = copy.sd.split("~").filter((d: string) => !names.includes(readDisclosure(d)?.name ?? "")).join("~");
  return copy;
};
const ordered = (results: StepResult[]) => {
  const at = results.findIndex((r) => r.status === "fail");
  if (at < 0) return chain(results).every((r) => r.status !== "unchecked");
  return results.slice(at + 1).every((r) => r.status === "unchecked" && r.detail === "Not checked: an earlier step failed");
};
const HOSTILE: unknown[] = [null, "", "x", -1, 0, 1.5, 2 ** 53, true, {}, [], ["x"], "\ud800", { toString: 1 }];

describe("verifyReceipt on hostile input", () => {
  it.each([
    [null, "receipt: malformed"], ["receipt", "receipt: malformed"], [2, "receipt: malformed"], [[], "receipt: malformed"],
    [{}, "receipt: v malformed"],
  ])("refuses %j at the receipt format", async (value, detail) => {
    const results = await verifyReceipt(value, TRUST);
    expect(results[0]).toEqual({ step: "Receipt format", status: "fail", detail });
    expect(ordered(results)).toBe(true);
  });

  it.each([
    ["v", 3, "receipt: v malformed"],
    ["registry.proof.seq", 1.5, "receipt: registry.proof.seq malformed"],
    ["registry.seal.ts", 2 ** 53, "receipt: registry.seal.ts malformed"],
    ["policy.policy_version", true, "receipt: policy.policy_version malformed"],
    ["reasoning", { v: 1, model: "m", response_id: "r" }, "receipt: reasoning.blobs malformed"],
    ["reasoning", { v: 1, model: "m", response_id: "r", blobs: [1] }, "receipt: reasoning.blobs malformed"],
    ["registry.entry", { seq: 1, kind: "execution", body: "{}", extra: 1 }, "receipt: registry.entry malformed"],
  ])("names %s when it is malformed", async (path, value, detail) => {
    expect((await failed(tamper(path, value)))).toEqual({ step: "Receipt format", status: "fail", detail });
  });

  it.each([
    ["registry.entry.body", "not json", "Registry inclusion", "Registry entry body is not JSON"],
    ["registry.entry.body", "null", "Registry inclusion", "Registry entry is not an executed payment"],
    ["registry.entry.kind", "denial", "Registry inclusion", "Registry entry is not an executed payment"],
    ["registry.entry.body", '{"payment_id":{"toString":1},"quote_id":"q:000001","reason":"ok: executed","status":"confirmed"}',
      "Registry inclusion", 'Registry entry is for {"toString":1}, not pay:000001'],
    ["registry.entry.body", '{"payment_id":"pay:000001","quote_id":"q:000009","reason":"ok: executed","status":"confirmed"}',
      "Registry inclusion", "Registry entry names a quote the action does not cite"],
    ["registry.proof.seq", 2, "Registry inclusion", "Proof is for another entry"],
    ["registry.proof.leaf", "00".repeat(32), "Registry inclusion", "Entry hashes to 70566024e09c…, not the proven leaf 000000000000…"],
    ["registry.proof.siblings", ["zz"], "Registry inclusion", "Inclusion proof is malformed"],
    ["registry.seal.root", "00".repeat(32), "Registry inclusion", "Proof recomputes root 70566024e09c…, not the sealed 000000000000…"],
    ["registry.seal.signature", "!!", "Registry seal", "Seal signature is malformed"],
    ["reasoning", { v: 1, model: "m", response_id: "r", blobs: ["a\nb"] }, "Reasoning anchor", "Reasoning anchor is malformed"],
    ["reasoning", { v: 1, model: "m", response_id: "r", blobs: [""] }, "Reasoning anchor", "Reasoning anchor is malformed"],
    ["reasoning", { v: 2, model: "m", response_id: "r", blobs: ["b"] }, "Reasoning anchor", "Reasoning anchor is malformed"],
    ["reasoning", { v: 1, model: "m", response_id: "r", blobs: [] }, "Reasoning anchor",
      "Anchor digest " ],
  ])("a receipt with %s set to %j fails at %s", async (path, value, step, detail) => {
    const results = await verifyReceipt(JSON.parse(tamper(path, value)), TRUST);
    const at = results.findIndex((r) => r.status === "fail");
    expect(results[at]?.step).toBe(step);
    expect(results[at]?.detail.startsWith(detail)).toBe(true);
    expect(chain(results.slice(0, at)).every((r) => r.status === "pass")).toBe(true);
    expect(ordered(results)).toBe(true);
  });

  it("fails at the certificate when the pinned key is not 32 bytes", async () => {
    expect(await failed(RECEIPT, { ...TRUST, gateKey: new Uint8Array(31) })).toEqual({
      step: "Gate certificate",
      status: "fail",
      detail: "Not signed by the gate key (malformed: bad public key)",
    });
  });

  it("never throws and never passes after a failure, whatever a field is set to", async () => {
    const golden = JSON.parse(RECEIPT);
    const paths: string[] = [];
    const visit = (node: unknown, at: string[]) => {
      if (at.length > 0) paths.push(at.join("."));
      if (typeof node === "object" && node !== null && !Array.isArray(node)) {
        for (const [k, v] of Object.entries(node)) visit(v, [...at, k]);
      }
    };
    visit(golden, []);
    for (const path of paths) {
      const original = JSON.stringify(path.split(".").reduce((at, k) => at[k], golden));
      for (const value of HOSTILE.filter((v) => JSON.stringify(v) !== original)) {
        const results = await verifyReceipt(JSON.parse(tamper(path, value)), TRUST);
        expect(results.map((r) => r.step)).toEqual([...STEPS]);
        expect(ordered(results)).toBe(true);
        if (path !== "policy.rule_id") expect(verdictOf(results).label, `${path} = ${JSON.stringify(value)}`).toBe("NOT VERIFIED");
      }
    }
  });

  it("never throws and never verifies when the gate itself signs a hostile disclosure", async () => {
    const names = ["targets", "action_salt", ...Object.values(GROUPS).flat(), "signature"];
    for (const name of names) {
      for (const value of HOSTILE) {
        const results = await verifyReceipt(JSON.parse(await regate(name, value)), TRUST);
        expect(ordered(results)).toBe(true);
        expect(verdictOf(results).label, `${name} = ${JSON.stringify(value)}`).toBe("NOT VERIFIED");
      }
    }
  });

  it("refuses an action salt that is not lowercase hex at the disclosures", async () => {
    expect(await failed(await regate("action_salt", "AB".repeat(32)))).toEqual({
      step: "Receipt disclosures",
      status: "fail",
      detail: "receipt: sd.cava.action_salt malformed",
    });
  });

  it("withholds the action and the consent when the salt alone is withheld", async () => {
    const results = await verifyReceipt(without(RECEIPT, ["action_salt"]), TRUST);
    expect(results.map((r) => r.status)).toEqual([
      "pass", "pass", "pass", "withheld", "pass", "withheld", "pass", "pass", "unchecked", "pass", "pass", "pass",
    ]);
    expect(results[2]?.detail).toBe("Signed by the gate key; disclosed: amount, payee, account, reference, holder; withheld: action_salt");
  });

  it("treats a half-disclosed holder group as withheld", async () => {
    const results = await verifyReceipt(without(RECEIPT, ["key_signature"]), TRUST);
    expect(chain(results).every((r) => r.status === "pass")).toBe(true);
    expect(results[2]?.detail).toBe("Signed by the gate key; disclosed: amount, payee, account, reference; withheld: holder");
    expect(results[5]?.detail).toContain("holder identity withheld");
  });

  it("withholds the consent when one field group is withheld", async () => {
    const results = await verifyReceipt(without(RECEIPT, ["source"]), TRUST);
    expect(results[5]).toEqual({ step: "Holder consent", status: "withheld", detail: "Withheld: the holder's signed fields were not all disclosed" });
    expect(results[2]?.detail).toBe("Signed by the gate key; disclosed: amount, payee, reference, holder; withheld: account");
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED, FIELDS WITHHELD",
      text: "Every disclosed link verified in this browser; 1 check needs fields the holder withheld; no public timestamp yet",
    });
  });
});

describe("verifyCertificate on hostile input", () => {
  it.each(["", "x", "a.b.c", "~~"])("fails %j at the gate certificate", async (token) => {
    const results = await verifyCertificate(token, TRUST);
    expect(results[1]).toEqual({ step: "Gate certificate", status: "fail", detail: "Not signed by the gate key (malformed: token undecodable)" });
    expect(verdictOf(results).label).toBe("NOT VERIFIED");
  });
});

describe("parseReceipt and parseDisclosed", () => {
  it("returns a fresh receipt equal to the golden", () => {
    const golden = JSON.parse(RECEIPT);
    const parsed = parseReceipt(golden);
    expect(parsed).toEqual(golden);
    expect(parsed).not.toBe(golden);
  });

  it("throws ReceiptError naming the path", () => {
    expect(() => parseReceipt(JSON.parse(tamper("registry.seal", null)))).toThrow(new ReceiptError("receipt: registry.seal malformed"));
    const golden = JSON.parse(RECEIPT);
    delete golden.reasoning;
    expect(() => parseReceipt(golden)).toThrow("receipt: reasoning malformed");
  });

  it("rebuilds the disclosed payload and refuses unknown or malformed claims", async () => {
    const d = await disclosedOf(parseReceipt(JSON.parse(RECEIPT)), TRUST.gateKey);
    expect(d?.consent.recipient).toBe("acme-991");
    expect(d && parseDisclosed(d)).toEqual(d);
    expect(() => parseDisclosed({ ...d, consent: { ...d?.consent, extra: 1 } })).toThrow("receipt: sd.consent malformed");
    expect(() => parseDisclosed({ ...d, consent: { ...d?.consent, consent_key: "k9uf" } })).toThrow("receipt: sd.consent.consent_key malformed");
    expect(() => parseDisclosed({ ...d, cava: { ...d?.cava, targets: undefined } })).toThrow("receipt: sd.cava.targets malformed");
    expect(() => parseDisclosed({ ...d, cava: { ...d?.cava, action_salt: "0".repeat(63) } })).toThrow("receipt: sd.cava.action_salt malformed");
    expect(() => parseDisclosed(null)).toThrow("receipt: sd malformed");
  });

  it("is null when the disclosures do not verify", async () => {
    expect(await disclosedOf(parseReceipt(JSON.parse(RECEIPT)), fromBase64(HOLDER_KEY))).toBeNull();
    expect(await disclosedOf(parseReceipt(JSON.parse(await regate("action_salt", "x"))), TRUST.gateKey)).toBeNull();
  });
});

describe("verdictOf on partial results", () => {
  it("is INCOMPLETE for no results and for unchecked steps", () => {
    expect(verdictOf([]).label).toBe("INCOMPLETE");
    const unchecked = STEPS.map((step) => ({ step, status: "unchecked" as const, detail: "" }));
    expect(verdictOf(unchecked)).toEqual({ label: "INCOMPLETE", text: "Not every step of the chain was checked" });
  });
});

describe("holder consent signed by real holder keys", () => {
  it("derives the golden keys and signatures from their seeds", async () => {
    expect(await seedPublicKey(0x81)).toBe(CONSENT_KEY);
    expect(await seedPublicKey(0x02)).toBe(HOLDER_KEY);
    expect(await seedSign(0x81, consentBytes(CONSENT))).toBe(CONSENT.signature);
    expect(await seedSign(0x02, keyBytes(fromBase64(CONSENT_KEY), CONSENT.nonce))).toBe(CONSENT.key_signature);
  });

  it("fails a consent the one-time key signed for another payee than the certified action", async () => {
    const signature = await seedSign(0x81, consentBytes({ ...CONSENT, recipient: "evil-666" }));
    const results = await verifyReceipt(JSON.parse(await reissue({ recipient: "evil-666", signature })), TRUST);
    expect(results.map((r) => r.status)).toEqual([
      "pass", "pass", "pass", "pass", "pass", "fail", "unchecked", "unchecked", "unchecked", "unchecked", "unchecked",
      "unchecked",
    ]);
    expect(results[5]).toEqual({ step: "Holder consent", status: "fail", detail: "Consent does not match the canonical action" });
  });

  it("fails a consent key a foreign holder key validly certified", async () => {
    const foreign = await seedPublicKey(0x03);
    const key_signature = await seedSign(0x03, keyBytes(fromBase64(CONSENT_KEY), CONSENT.nonce));
    const receipt = JSON.parse(await reissue({ holder_key: foreign, key_signature }));
    const results = await verifyReceipt(receipt, TRUST);
    expect(results[5]).toEqual({ step: "Holder consent", status: "fail", detail: "Signed by a key this desk does not trust" });
    expect(results.slice(0, 5).every((r) => r.status === "pass")).toBe(true);
    const trusting = await verifyReceipt(receipt, { ...TRUST, holderKeys: [fromBase64(foreign)] });
    expect(verdictOf(trusting).label).toBe("VERIFIED");
  });
});

describe("gate-signed funds view", () => {
  it("is read from the signed payload, never from a top-level key", async () => {
    const r = parseReceipt(JSON.parse(RECEIPT_ZKTLS));
    expect("funds" in r).toBe(false);
    const d = (await disclosedOf(r, fromBase64(GATE_KEY)))!;
    expect(d.funds).toEqual({
      kind: "zktls",
      evidence_ref: "ev:zktls-attestation:c1cda26362828b69266512052b97cb37",
      presentation_sha256: "c1cda26362828b69266512052b97cb3729e3b052e4ade47c0a1e3383defe73c7",
      server_name: "sandbox.increase.com",
      session_time: 1800000995,
      notary_key: "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f",
    });
  });

  it("refuses a funds kind it does not know", async () => {
    const odd = (p: Record<string, unknown>) => {
      p.funds = { ...(p.funds as object), kind: "bank" };
    };
    expect((await failed(await resign(odd, RECEIPT_ZKTLS)))?.detail).toBe("receipt: sd.funds.kind malformed");
  });
});

const ZK_REF = "ev:zktls-attestation:c1cda26362828b69266512052b97cb37";
const COOP_REF = "ev:cooperative-signed:c97da00074742018dff37a1130a145f3";
const funds = (change: Record<string, unknown> | null) => (p: Record<string, unknown>) => {
  p.funds = change === null ? null : { ...(p.funds as object), ...change };
};

describe("funds proof step", () => {
  it("binds a zkTLS presentation the desk checked", async () => {
    const results = await verifyReceipt(JSON.parse(RECEIPT_ZKTLS), TRUST);
    expect(chain(results).every((r) => r.status === "pass")).toBe(true);
    expect(results.at(-1)).toEqual({
      step: "Funds proof",
      status: "pass",
      detail: `ZKTLS presentation ${ZK_REF} of sandbox.increase.com, checked by the desk's verifier with notary key 02989c0b76cb…; this browser checks its binding to the certificate, not the TLS proof`,
    });
  });

  it.each([
    [null, "Funds evidence was removed from the receipt"],
    [{ evidence_ref: "ev:zktls-attestation:00000000000000000000000000000000" }, "Funds evidence is not among the certified evidence"],
    [{ kind: "cooperative" }, "Funds kind does not match its evidence reference"],
    [{ presentation_sha256: "0".repeat(64) }, "Funds proof digest does not match its reference"],
    [{ server_name: "api.increase.com" }, "Funds proof was not made against sandbox.increase.com"],
    [{ notary_key: null }, "Funds proof is malformed"],
    [{ notary_key: "02989c0b76cb" }, "Funds proof is malformed"],
    [{ notary_key: "04989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f" }, "Funds proof is malformed"],
    [{ notary_key: "02989C0B76CB563971FDC9BEF31EC06C3560F3249D6EE9E5D83C57625596E05F6F" }, "Funds proof is malformed"],
    [{ session_time: null }, "Funds proof is malformed"],
  ])("a gate-signed funds view %j fails the funds step", async (change, detail) => {
    const results = await verifyReceipt(JSON.parse(await resign(funds(change), RECEIPT_ZKTLS)), TRUST);
    expect(results.at(-1)).toEqual({ step: "Funds proof", status: "fail", detail });
    expect(chain(results).slice(0, -1).every((r) => r.status === "pass")).toBe(true);
  });

  it("refuses a funds view edited without the gate key", async () => {
    const r = JSON.parse(RECEIPT_ZKTLS);
    const [token, ...rest] = r.sd.split("~");
    const [h, p, sig] = token.split(".");
    const payload = JSON.parse(new TextDecoder().decode(fromBase64(p.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (p.length % 4)) % 4))));
    payload.funds = null;
    const edited = btoa(JSON.stringify(payload)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    r.sd = [`${h}.${edited}.${sig}`, ...rest].join("~");
    expect((await failed(JSON.stringify(r)))?.detail).toBe("Disclosures do not verify (sd-jwt: bad signature)");
  });

  it("labels a cooperative statement as not a bank proof", async () => {
    const results = await verifyReceipt(JSON.parse(RECEIPT_COOP), TRUST);
    expect(chain(results).every((r) => r.status === "pass")).toBe(true);
    expect(results.at(-1)).toEqual({
      step: "Funds proof",
      status: "pass",
      detail: `COOPERATIVE statement ${COOP_REF}, signed by the desk; not a bank proof`,
    });
  });
});
