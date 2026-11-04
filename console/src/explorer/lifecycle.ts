import { fromBase64, verifyEd25519, type Bytes } from "./bytes";
import { certificateId, leafHash, rootOf, sealBytes } from "./chain";
import { TIMEOUT_MS, type Fetch } from "./publish";
import type { Disclosed, Entry, Proof, Receipt, Seal } from "./receipt";
import { isAchTransfer } from "./verify";

type Obj = Record<string, unknown>;

const isObj = (value: unknown): value is Obj => typeof value === "object" && value !== null && !Array.isArray(value);
const int = (value: unknown): value is number => Number.isSafeInteger(value);
const str = (value: unknown): value is string => typeof value === "string";

const NOT_SEALED = "entry is not in the sealed registry";
const NOT_SIGNED = "seal is not signed by the gate key";

/** The sealed settlement and return entries of a payment, or null when the server has none or cannot be reached. */
export async function fetchLifecycle(id: string, fetchFn: Fetch): Promise<unknown | null> {
  const abort = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // The timer settles the wait even when a fetch ignores the signal.
  const expired = new Promise<null>((resolve) => {
    timer = setTimeout(() => {
      abort.abort();
      resolve(null);
    }, TIMEOUT_MS);
  });
  const answer = async () => {
    const response = await fetchFn(`/api/lifecycle/${encodeURIComponent(id)}`, { signal: abort.signal });
    return response.status === 200 ? ((await response.json()) as unknown) : null;
  };
  try {
    return await Promise.race([answer(), expired]);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function entryOf(value: unknown): Entry | null {
  if (!isObj(value) || !int(value.seq) || !str(value.kind) || !str(value.body)) return null;
  return { seq: value.seq, kind: value.kind, body: value.body };
}

function proofOf(value: unknown): Proof | null {
  if (!isObj(value) || !int(value.seq) || !int(value.leaves) || !str(value.leaf) || !str(value.root)) return null;
  const { siblings } = value;
  if (!Array.isArray(siblings) || !siblings.every(str)) return null;
  return { seq: value.seq, leaves: value.leaves, leaf: value.leaf, siblings, root: value.root };
}

function sealOf(value: unknown): Seal | null {
  if (!isObj(value) || !int(value.v) || !str(value.anchor_id) || !int(value.seq_from) || !int(value.seq_to)) return null;
  if (!str(value.root) || !int(value.ts) || !str(value.signature)) return null;
  const { v, anchor_id, seq_from, seq_to, root, ts, signature } = value;
  return { v, anchor_id, seq_from, seq_to, root, ts, signature };
}

async function signed(seal: Seal, gateKey: Bytes): Promise<boolean> {
  try {
    return await verifyEd25519(gateKey, fromBase64(seal.signature), sealBytes(seal));
  } catch {
    return false;
  }
}

function bodyOf(entry: Entry): Obj {
  try {
    const body: unknown = JSON.parse(entry.body);
    return isObj(body) ? body : {};
  } catch {
    return {};
  }
}

// A value from a sealed body shown as text; never calls the value's own methods.
const shown = (value: unknown): string => (typeof value === "string" ? value : (JSON.stringify(value) ?? "undefined"));

type Checked = { seq: unknown; kind: string; anchor: string; body: Obj } | { seq: unknown; why: string };

// The checks in order: sealed inclusion, the seal's signature, the payment, then the link to its execution entry.
async function check(event: unknown, receipt: Receipt, gateKey: Bytes): Promise<Checked> {
  const raw = isObj(event) ? event : {};
  const seq = isObj(raw.entry) ? raw.entry.seq : undefined;
  const [entry, proof, seal] = [entryOf(raw.entry), proofOf(raw.proof), sealOf(raw.seal)];
  if (entry === null || proof === null || seal === null) return { seq, why: NOT_SEALED };
  const included =
    entry.seq === proof.seq &&
    (await leafHash(entry)) === proof.leaf &&
    (await rootOf(proof)) === proof.root &&
    proof.root === seal.root &&
    proof.leaves === seal.seq_to;
  if (!included) return { seq, why: NOT_SEALED };
  if (!(await signed(seal, gateKey))) return { seq, why: NOT_SIGNED };
  const body = bodyOf(entry);
  if (body.payment_id !== receipt.payment_id) return { seq, why: `entry is for ${shown(body.payment_id)}, not ${receipt.payment_id}` };
  const execution = receipt.registry.entry.seq;
  if (body.execution_seq !== execution || entry.seq <= execution) return { seq, why: `entry does not follow execution #${execution}` };
  return { seq, kind: entry.kind, anchor: seal.anchor_id, body };
}

// What the verified entries say the bank did; a return is final, so it outranks a settlement.
function outcome(verified: readonly Obj[], kinds: readonly string[]): string | null {
  const returned = verified.find((b, i) => kinds[i] === "return" && str(b.code) && str(b.reason) && str(b.returned_at));
  if (returned !== undefined) {
    return `SIMULATED RETURN ${shown(returned.code)} ${shown(returned.reason)} at ${shown(returned.returned_at)}; the money went back to the payer`;
  }
  const settled = verified.find((b, i) => kinds[i] === "settlement" && str(b.settled_at));
  return settled === undefined ? null : `Settled at ${shown(settled.settled_at)}`;
}

/**
 * Requested, approved and processed for an ACH payment, then one row per sealed lifecycle entry, each verified here
 * under the gate key. Empty when there is no answer or the receipt's transfer is not an ACH transfer.
 */
export async function lifecycleRows(value: unknown, receipt: Receipt, disclosed: Disclosed, gateKey: Bytes): Promise<[string, string][]> {
  const bank = disclosed.bank;
  if (value === null || bank === null || !isAchTransfer(bank.transfer_id)) return [];
  const { amount_cents, currency } = disclosed.consent;
  const requested = amount_cents === undefined || currency === undefined ? "Withheld" : `${(amount_cents / 100).toFixed(2)} ${currency}`;
  const events = isObj(value) && Array.isArray(value.events) ? value.events : [];
  const checked = await Promise.all(events.map((e) => check(e, receipt, gateKey)));
  const failure = checked.find((c): c is { seq: unknown; why: string } => "why" in c);
  const passed = checked.filter((c): c is Exclude<Checked, { why: string }> => !("why" in c));
  // Only the receipt's own signed status stands until every entry verifies.
  const said = outcome(passed.map((c) => c.body), passed.map((c) => c.kind));
  // With no sealed outcome yet, the receipt's own signed status speaks; a receipt sealed after the return never reads as accepted.
  const signedStatus =
    bank.status === "returned"
      ? "Returned by the bank before this receipt was sealed; the money went back to the payer"
      : `Accepted by the bank (${bank.status}); not settled yet`;
  const processed = failure !== undefined ? `Unverified: ${failure.why}` : (said ?? signedStatus);
  return [
    ["Requested", requested],
    ["Approved", `Gate certificate ${certificateId(receipt.certificate) ?? "unreadable"}`],
    ["Processed", processed],
    ...checked.map((c): [string, string] => [
      `Sealed entry #${shown(c.seq)}`,
      "why" in c ? `does not verify: ${c.why}` : `${c.kind} · included under seal ${c.anchor}`,
    ]),
  ];
}
