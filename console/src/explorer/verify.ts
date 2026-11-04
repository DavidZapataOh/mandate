import { fromBase64, toBase64, verifyEd25519, type Bytes } from "./bytes";
import { hmacSha256Hex, keyBytes } from "./canon";
import { anchorDigest, cavaJson, certificateId, consentBytes, leafHash, readClaims, reasoningCommitment, rootOf, sealBytes } from "./chain";
import { parseDisclosed, parseReceipt, ReceiptError, type Disclosed, type Receipt } from "./receipt";
import { processSdJwt, RECEIPT_TYP } from "./sdjwt";

/** The proof chain's steps, in the order they are checked. */
export const STEPS = [
  "Receipt format",
  "Gate certificate",
  "Receipt disclosures",
  "Canonical action",
  "Policy",
  "Holder consent",
  "Registry inclusion",
  "Registry seal",
  "Reasoning anchor",
  "Bank transfer",
] as const;

export type StepName = (typeof STEPS)[number];
export type Status = "pass" | "fail" | "withheld" | "unchecked";

export interface StepResult {
  step: StepName;
  status: Status;
  detail: string;
}

/** What the verifier trusts: the gate key, and the published holder keys (null when none was published). */
export interface Trust {
  gateKey: Bytes;
  holderKeys: readonly Bytes[] | null;
}

/** The consent fields a holder discloses together, in display order. */
export const GROUPS = {
  amount: ["amount_cents", "currency"],
  payee: ["recipient"],
  account: ["source"],
  reference: ["reference"],
  holder: ["holder_key", "key_signature"],
} as const;

export type Group = keyof typeof GROUPS;

export interface Verdict {
  label: "VERIFIED" | "VERIFIED, FIELDS WITHHELD" | "NOT VERIFIED" | "INCOMPLETE";
  text: string;
}

const UNCHECKED = "Not checked: an earlier step failed";
const RECEIPT_NEEDED = "Paste the full receipt to check this step";
const ACTION_WITHHELD = "Withheld: the action's targets and salt were not disclosed; the certificate still fixes its salted hash";
const CONSENT_WITHHELD = "Withheld: the holder's signed fields were not all disclosed";
const HOLDER_ON_GATE = "Signed by a one-time key; holder identity withheld (the gate checked its certificate)";
const FIELD_GROUPS = ["amount", "payee", "account", "reference"] as const satisfies readonly Group[];
// Claims that open every hidden field; the holder discloses them only with all four field groups.
const FULL = [["cava", "targets"], ["cava", "action_salt"], ["consent", "signature"]] as const;

/** A check found the link broken; the chain stops here. */
class Fail extends Error {}
/** A check needs a field the holder did not disclose; the chain goes on. */
class Withheld extends Error {}

/** What the checks share; a check reads what an earlier step stored. */
interface Slots {
  receipt: Receipt;
  claims: Record<string, unknown>;
  disclosed: Disclosed;
}

class Context {
  readonly #slots: Partial<Slots> = {};
  constructor(
    readonly value: unknown,
    readonly trust: Trust,
  ) {}
  set<K extends keyof Slots>(key: K, value: Slots[K]): void {
    this.#slots[key] = value;
  }
  get<K extends keyof Slots>(key: K): Slots[K] {
    const value = this.#slots[key];
    if (value === undefined) throw new Error(`verify: ${key} read before it was checked`);
    return value as Slots[K];
  }
}

type Check = (ctx: Context) => Promise<string>;

// A value from a signed payload shown as text; never calls the value's own methods.
function shown(value: unknown): string {
  return typeof value === "string" ? value : (JSON.stringify(value) ?? "undefined");
}
const short = (value: unknown) => `${shown(value).slice(0, 12)}…`;

// The only bank a sandbox claim may name, and the shape of the transfer ids it issues.
const SANDBOX_PROVIDER = "increase";
const INCREASE_TRANSFER = /^(?:sandbox_)?account_transfer_[A-Za-z0-9]{1,64}$/;

function own(obj: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

function sameStrings(a: readonly string[], b: unknown): boolean {
  return Array.isArray(b) && a.length === b.length && a.every((s, i) => s === b[i]);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// Bytes decoded from input, or a failure with `detail` when they are not canonical base64.
function decoded(text: string, detail: string): Bytes {
  try {
    return fromBase64(text);
  } catch {
    throw new Fail(detail);
  }
}

function disclosedGroup(d: Disclosed, group: Group): boolean {
  return GROUPS[group].every((name) => d.consent[name] !== undefined);
}

function disclosureSummary(d: Disclosed): string {
  const groups = Object.keys(GROUPS) as Group[];
  const open = groups.filter((g) => disclosedGroup(d, g));
  const hidden = groups.filter((g) => !disclosedGroup(d, g));
  const missing = FULL.filter(([where, name]) => (d[where] as Record<string, unknown>)[name] === undefined).map(([, n]) => n);
  if (hidden.length === 0 && missing.length === 0) return "Signed by the gate key; every field disclosed";
  if (open.length === 0) return `Signed by the gate key; withheld by the holder: ${hidden.join(", ")}`;
  return `Signed by the gate key; disclosed: ${open.join(", ")}; withheld: ${[...hidden, ...missing].join(", ")}`;
}

/** The gate-signed payload with the receipt's Disclosures in place, or null when it does not verify or parse. */
export async function disclosedOf(r: Receipt, gateKey: Bytes): Promise<Disclosed | null> {
  const processed = await processSdJwt(r.sd, gateKey, RECEIPT_TYP);
  if ("reason" in processed) return null;
  try {
    return parseDisclosed(processed.payload);
  } catch (error) {
    if (error instanceof ReceiptError) return null;
    throw error;
  }
}

async function certificate(ctx: Context, token: string): Promise<string> {
  const read = await readClaims(token, ctx.trust.gateKey);
  if ("reason" in read) throw new Fail(`Not signed by the gate key (${read.reason})`);
  ctx.set("claims", read.claims);
  return `EdDSA signature verifies with gate key ${toBase64(ctx.trust.gateKey).slice(0, 12)}…`;
}

/** One check per step: the extension point for later steps (add a name to STEPS and its check here). */
const CHECKS: Readonly<Record<StepName, Check>> = {
  "Receipt format": async (ctx) => {
    try {
      ctx.set("receipt", parseReceipt(ctx.value));
    } catch (error) {
      if (error instanceof ReceiptError) throw new Fail(error.message);
      throw error;
    }
    return `Receipt for ${ctx.get("receipt").payment_id}`;
  },

  "Gate certificate": async (ctx) => certificate(ctx, ctx.get("receipt").certificate),

  "Receipt disclosures": async (ctx) => {
    const r = ctx.get("receipt");
    const processed = await processSdJwt(r.sd, ctx.trust.gateKey, RECEIPT_TYP);
    if ("reason" in processed) throw new Fail(`Disclosures do not verify (${processed.reason})`);
    let d: Disclosed;
    try {
      d = parseDisclosed(processed.payload);
    } catch (error) {
      if (error instanceof ReceiptError) throw new Fail(error.message);
      throw error;
    }
    if (d.sub !== r.payment_id) throw new Fail(`Disclosures are for ${d.sub}, not ${r.payment_id}`);
    if (d.cert_jti !== certificateId(r.certificate)) throw new Fail("Disclosures name another certificate");
    ctx.set("disclosed", d);
    return disclosureSummary(d);
  },

  "Canonical action": async (ctx) => {
    const claims = ctx.get("claims");
    const { action_salt, targets, ...rest } = ctx.get("disclosed").cava;
    if (targets === undefined || action_salt === undefined) throw new Withheld(ACTION_WITHHELD);
    const hash = await hmacSha256Hex(action_salt, cavaJson({ ...rest, targets }));
    const certified = own(claims, "action_hash");
    if (hash !== certified) throw new Fail(`Action hash ${short(hash)} differs from the certified ${short(certified)}`);
    if (rest.freshness.nonce !== own(claims, "freshness_nonce")) throw new Fail("Freshness nonce differs from the certificate");
    if (!sameStrings(rest.evidence_refs, own(claims, "evidence_refs"))) throw new Fail("Evidence references differ from the certificate");
    return `HMAC-SHA256 of the canonical bytes under the disclosed salt is the certified hash ${short(hash)}`;
  },

  Policy: async (ctx) => {
    const { policy } = ctx.get("receipt");
    const claims = ctx.get("claims");
    const [id, version, verdict] = [own(claims, "policy_id"), own(claims, "policy_version"), own(claims, "verdict")];
    if (id !== policy.policy_id || version !== policy.policy_version) {
      throw new Fail(`Certificate names policy ${shown(id)} v${shown(version)}, not ${policy.policy_id} v${policy.policy_version}`);
    }
    if (verdict !== "MET") throw new Fail(`Certified verdict is ${shown(verdict)}, not MET`);
    // Neither the certificate nor the SD-JWT signs the rule id, so it is shown as the desk's word only.
    return `Policy ${policy.policy_id} v${policy.policy_version}: MET (rule ${policy.rule_id}, reported by the desk, not signed)`;
  },

  "Holder consent": async (ctx) => {
    const { cava, consent: c } = ctx.get("disclosed");
    const { amount_cents, currency, recipient, reference, source, signature } = c;
    // The targets count only once the action step proved them against the certified hash.
    const targets = cava.action_salt === undefined ? undefined : cava.targets;
    if (
      targets === undefined || signature === undefined || amount_cents === undefined || currency === undefined ||
      recipient === undefined || reference === undefined || source === undefined
    ) {
      throw new Withheld(CONSENT_WITHHELD);
    }
    const signed = { amount_cents, currency, recipient, reference, source, nonce: c.nonce, expires_at: c.expires_at };
    let consentKey: Bytes, message: Bytes;
    try {
      consentKey = fromBase64(c.consent_key);
      message = consentBytes({ ...c, ...signed, signature, holder_key: "", key_signature: "" });
    } catch {
      throw new Fail("Consent is malformed");
    }
    const sig = decoded(signature, "Consent is malformed");
    if (!(await verifyEd25519(consentKey, sig, message))) throw new Fail("Holder signature does not verify over the consent bytes");
    const paired = c.holder_key !== undefined && c.key_signature !== undefined;
    if (paired) {
      let holderKey: Bytes, keySig: Bytes, certified: Bytes;
      try {
        holderKey = fromBase64(c.holder_key!);
        keySig = fromBase64(c.key_signature!);
        certified = keyBytes(consentKey, c.nonce);
      } catch {
        throw new Fail("Consent is malformed");
      }
      if (!(await verifyEd25519(holderKey, keySig, certified))) throw new Fail("The holder key did not certify the consent key");
      const list = ctx.trust.holderKeys;
      if (list !== null && !list.some((k) => sameBytes(k, holderKey))) throw new Fail("Signed by a key this desk does not trust");
    }
    const one = (prefix: string, expected: string) => {
      const found = targets.filter((t) => t.startsWith(prefix));
      return found.length === 1 && found[0] === `${prefix}${expected}`;
    };
    if (!(one("amount:", `${currency}:${amount_cents}`) && one("from:", source) && one("ref:", reference) && one("to:", recipient))) {
      throw new Fail("Consent does not match the canonical action");
    }
    const what = `${amount_cents} ${currency} cents to ${recipient} (ref ${reference})`;
    if (!paired) return `${HOLDER_ON_GATE}: ${what}`;
    const unlisted = ctx.trust.holderKeys === null ? " (no published holder list to compare)" : "";
    return `Signed by a one-time key the paired holder key certified: ${what}${unlisted}`;
  },

  "Registry inclusion": async (ctx) => {
    const r = ctx.get("receipt");
    const { entry, proof, seal } = r.registry;
    let body: unknown;
    try {
      body = JSON.parse(entry.body);
    } catch {
      throw new Fail("Registry entry body is not JSON");
    }
    const field = (key: string) => (typeof body === "object" && body !== null && !Array.isArray(body) ? own(body as Record<string, unknown>, key) : undefined);
    if (entry.kind !== "execution" || field("status") !== "confirmed" || field("reason") !== "ok: executed") {
      throw new Fail("Registry entry is not an executed payment");
    }
    if (field("payment_id") !== r.payment_id) throw new Fail(`Registry entry is for ${shown(field("payment_id"))}, not ${r.payment_id}`);
    const quote = field("quote_id");
    if (typeof quote !== "string" || !ctx.get("disclosed").cava.evidence_refs.includes(quote)) {
      throw new Fail("Registry entry names a quote the action does not cite");
    }
    if (entry.seq !== proof.seq) throw new Fail("Proof is for another entry");
    const leaf = await leafHash(entry);
    if (leaf !== proof.leaf) throw new Fail(`Entry hashes to ${short(leaf)}, not the proven leaf ${short(proof.leaf)}`);
    const root = await rootOf(proof);
    if (root === null) throw new Fail("Inclusion proof is malformed");
    if (root !== proof.root || proof.root !== seal.root || proof.leaves !== seal.seq_to) {
      throw new Fail(`Proof recomputes root ${short(root)}, not the sealed ${short(seal.root)}`);
    }
    return `Entry ${entry.seq} of ${proof.leaves} recomputes the sealed root ${short(root)}`;
  },

  "Registry seal": async (ctx) => {
    const { seal } = ctx.get("receipt").registry;
    const signature = decoded(seal.signature, "Seal signature is malformed");
    if (!(await verifyEd25519(ctx.trust.gateKey, signature, sealBytes(seal)))) {
      throw new Fail(`Seal ${seal.anchor_id} is not signed by the gate key`);
    }
    return `Seal ${seal.anchor_id} over entries ${seal.seq_from}–${seal.seq_to} verifies`;
  },

  "Reasoning anchor": async (ctx) => {
    const { reasoning } = ctx.get("receipt");
    const commitment = own(ctx.get("claims"), "reasoning_commitment");
    if (reasoning === null) {
      if ((await reasoningCommitment([])) !== commitment) throw new Fail("Certificate commits to model reasoning the receipt does not carry");
      return "No model reasoning: the certificate commits to an empty chain";
    }
    let digest: string;
    try {
      if (reasoning.v !== 1) throw new Error("reasoning: unsupported anchor version");
      digest = await anchorDigest(reasoning);
    } catch {
      throw new Fail("Reasoning anchor is malformed");
    }
    if (digest !== commitment) throw new Fail(`Anchor digest ${short(digest)} differs from the certified commitment`);
    return `Anchor digest ${short(digest)} of ${reasoning.model} response ${reasoning.response_id} is the certified commitment`;
  },

  // Offline it can bind the transfer to this certificate and payment; only the bank can say it still holds it.
  "Bank transfer": async (ctx) => {
    const r = ctx.get("receipt");
    const { bank } = ctx.get("disclosed");
    if (bank === null) throw new Fail("Receipt names no bank transfer");
    if (bank.idempotency_key !== `mandate-cert-${certificateId(r.certificate)}`) {
      throw new Fail("Bank transfer was not requested under this certificate");
    }
    if (bank.rail === "sandbox") {
      if (bank.provider !== SANDBOX_PROVIDER) throw new Fail(`Sandbox transfer names provider ${shown(bank.provider)}, not ${SANDBOX_PROVIDER}`);
      if (!INCREASE_TRANSFER.test(bank.transfer_id)) throw new Fail(`Bank transfer ${shown(bank.transfer_id)} is not an Increase transfer id`);
    }
    if (bank.transfer_id !== r.payment_id) throw new Fail(`Bank transfer ${bank.transfer_id} is not the sealed payment ${r.payment_id}`);
    if (bank.status !== "complete") throw new Fail(`Bank reports the transfer ${bank.status}, not complete`);
    if (bank.rail === "sandbox") {
      return `SANDBOX transfer ${bank.transfer_id} at ${SANDBOX_PROVIDER}, requested under this certificate; the gate signs this claim, and the id is checkable in the Increase sandbox dashboard of the account that holds the key`;
    }
    return `SIMULATED ledger payment ${bank.transfer_id}, requested under this certificate; no bank holds it`;
  },
};

async function run(ctx: Context, steps: Readonly<Record<StepName, Check | string>>): Promise<StepResult[]> {
  const results: StepResult[] = [];
  let failed = false;
  for (const step of STEPS) {
    const check = steps[step];
    if (failed) {
      results.push({ step, status: "unchecked", detail: UNCHECKED });
      continue;
    }
    if (typeof check === "string") {
      results.push({ step, status: "unchecked", detail: check });
      continue;
    }
    try {
      results.push({ step, status: "pass", detail: await check(ctx) });
    } catch (error) {
      if (error instanceof Withheld) results.push({ step, status: "withheld", detail: error.message });
      else if (error instanceof Fail) {
        results.push({ step, status: "fail", detail: error.message });
        failed = true;
      } else throw error;
    }
  }
  return results;
}

/** Every step of a pasted receipt, in order, stopping at the first broken link. */
export async function verifyReceipt(value: unknown, trust: Trust): Promise<StepResult[]> {
  return run(new Context(value, trust), CHECKS);
}

/** A certificate on its own: only its signature can be checked. */
export async function verifyCertificate(token: string, trust: Trust): Promise<StepResult[]> {
  const steps = Object.fromEntries(STEPS.map((s) => [s, RECEIPT_NEEDED])) as Record<StepName, Check | string>;
  steps["Gate certificate"] = (ctx) => certificate(ctx, token);
  return run(new Context(token, trust), steps);
}

/** The chain's verdict: VERIFIED only when every step passed. */
export function verdictOf(results: readonly StepResult[]): Verdict {
  const failure = results.find((r) => r.status === "fail");
  if (failure !== undefined) return { label: "NOT VERIFIED", text: `Failed at ${failure.step}: ${failure.detail}` };
  const complete = results.length === STEPS.length && results.every((r, i) => r.step === STEPS[i]);
  if (complete && results.every((r) => r.status === "pass")) {
    // Without the holder group the paired key's certificate was checked by the gate, not here.
    const onGate = results.some((r) => r.step === "Holder consent" && r.detail.startsWith(`${HOLDER_ON_GATE}:`));
    const text = "Every link of the chain verified in this browser";
    return { label: "VERIFIED", text: onGate ? `${text}; the holder's identity rests on the gate` : text };
  }
  const withheld = results.filter((r) => r.status === "withheld").length;
  if (complete && withheld > 0 && results.every((r) => r.status !== "unchecked")) {
    const checks = withheld === 1 ? "1 check needs" : `${withheld} checks need`;
    return { label: "VERIFIED, FIELDS WITHHELD", text: `Every disclosed link verified in this browser; ${checks} fields the holder withheld` };
  }
  const certificateOnly = results.length === STEPS.length &&
    results.every((r) => (r.step === "Gate certificate" ? r.status === "pass" : r.status === "unchecked"));
  if (certificateOnly) return { label: "INCOMPLETE", text: "The certificate verifies; paste the full receipt to check the chain" };
  return { label: "INCOMPLETE", text: "Not every step of the chain was checked" };
}
