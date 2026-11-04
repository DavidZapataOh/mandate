import { describe, expect, it } from "vitest";
import { fromBase64 } from "./bytes";
import { AUDITOR, CONSENT, CONSENT_KEY, forge, GATE_KEY, HOLDER_KEY, RECEIPT, regate, reissue, resign, seedPublicKey, seedSign, tamper } from "./__fixtures__/receipts";
import { keyBytes } from "./canon";
import { consentBytes } from "./chain";
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

describe("verifyReceipt", () => {
  it("passes every step of a receipt the desk issued", async () => {
    const results = await verifyReceipt(JSON.parse(RECEIPT), TRUST);
    expect(results.map((r) => r.step)).toEqual([...STEPS]);
    expect(results.every((r) => r.status === "pass")).toBe(true);
    expect(results.map((r) => r.detail)).toEqual([
      "Receipt for pay:000001",
      "EdDSA signature verifies with gate key iojj3XQJ8ZX9…",
      "Signed by the gate key; every field disclosed",
      "HMAC-SHA256 of the canonical bytes under the disclosed salt is the certified hash 52e9b189b7db…",
      "Policy desk v1: MET (rule pay-with-consent, reported by the desk, not signed)",
      "Signed by a one-time key the paired holder key certified: 20000 USD cents to acme-991 (ref A-991)",
      "Entry 1 of 1 recomputes the sealed root 70566024e09c…",
      "Seal anch:000001 over entries 1–1 verifies",
      "No model reasoning: the certificate commits to an empty chain",
      "SIMULATED ledger payment pay:000001, requested under this certificate; no bank holds it",
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
    expect(results.slice(0, at).every((r) => r.status === "pass")).toBe(true);
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
      "Policy: pass", "Holder consent: withheld", "Registry inclusion: pass", "Registry seal: pass", "Reasoning anchor: pass",
      "Bank transfer: pass",
    ]);
    expect(results[2]?.detail).toBe("Signed by the gate key; withheld by the holder: amount, payee, account, reference, holder");
    expect(results[3]?.detail).toBe("Withheld: the action's targets and salt were not disclosed; the certificate still fixes its salted hash");
    expect(results[5]?.detail).toBe("Withheld: the holder's signed fields were not all disclosed");
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED, FIELDS WITHHELD",
      text: "Every disclosed link verified in this browser; 2 checks need fields the holder withheld",
    });
  });

  it("verifies a holder copy without its holder group and says the identity is withheld", async () => {
    const copy = JSON.parse(RECEIPT);
    const hidden = ["holder_key", "key_signature"];
    copy.sd = copy.sd.split("~").filter((d: string) => !hidden.includes(readDisclosure(d)?.name ?? "")).join("~");
    const results = await verifyReceipt(copy, TRUST);
    expect(results.every((r) => r.status === "pass")).toBe(true);
    expect(results[2]?.detail).toBe("Signed by the gate key; disclosed: amount, payee, account, reference; withheld: holder");
    expect(results[5]?.detail).toBe(
      "Signed by a one-time key; holder identity withheld (the gate checked its certificate): 20000 USD cents to acme-991 (ref A-991)",
    );
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED",
      text: "Every link of the chain verified in this browser; the holder's identity rests on the gate",
    });
  });

  it("says every link verified when the holder group is disclosed too", async () => {
    expect(verdictOf(await verifyReceipt(JSON.parse(RECEIPT), TRUST))).toEqual({
      label: "VERIFIED",
      text: "Every link of the chain verified in this browser",
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

const SANDBOX = {
  rail: "sandbox", provider: "increase", transfer_id: "pay:000001", status: "complete",
  idempotency_key: "mandate-cert-00000000000000000000000000000002",
};
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

  it("names a sandbox transfer and where to look it up", async () => {
    const results = await verifyReceipt(JSON.parse(await resign(bank(SANDBOX))), TRUST);
    expect(results.at(-1)).toEqual({
      step: "Bank transfer",
      status: "pass",
      detail: "SANDBOX transfer pay:000001 at increase, requested under this certificate; the account holder's Increase dashboard shows it",
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
      "unchecked",
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

describe("verdictOf", () => {
  it("is VERIFIED only when all ten steps passed", async () => {
    expect(verdictOf(await verifyReceipt(JSON.parse(RECEIPT), TRUST)).label).toBe("VERIFIED");
    expect(verdictOf((await verifyReceipt(JSON.parse(RECEIPT), TRUST)).slice(0, 9)).label).toBe("INCOMPLETE");
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
  if (at < 0) return results.every((r) => r.status !== "unchecked");
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
    expect(results.slice(0, at).every((r) => r.status === "pass")).toBe(true);
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
      "pass", "pass", "pass", "withheld", "pass", "withheld", "pass", "pass", "pass", "pass",
    ]);
    expect(results[2]?.detail).toBe("Signed by the gate key; disclosed: amount, payee, account, reference, holder; withheld: action_salt");
  });

  it("treats a half-disclosed holder group as withheld", async () => {
    const results = await verifyReceipt(without(RECEIPT, ["key_signature"]), TRUST);
    expect(results.every((r) => r.status === "pass")).toBe(true);
    expect(results[2]?.detail).toBe("Signed by the gate key; disclosed: amount, payee, account, reference; withheld: holder");
    expect(results[5]?.detail).toContain("holder identity withheld");
  });

  it("withholds the consent when one field group is withheld", async () => {
    const results = await verifyReceipt(without(RECEIPT, ["source"]), TRUST);
    expect(results[5]).toEqual({ step: "Holder consent", status: "withheld", detail: "Withheld: the holder's signed fields were not all disclosed" });
    expect(results[2]?.detail).toBe("Signed by the gate key; disclosed: amount, payee, reference, holder; withheld: account");
    expect(verdictOf(results)).toEqual({
      label: "VERIFIED, FIELDS WITHHELD",
      text: "Every disclosed link verified in this browser; 1 check needs fields the holder withheld",
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
      "pass", "pass", "pass", "pass", "pass", "fail", "unchecked", "unchecked", "unchecked", "unchecked",
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
