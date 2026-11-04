import { fromBase64, type Bytes } from "./bytes";
import { anonymityText, exposure, NEVER_IN_A_RECEIPT, WITHHELD } from "./exposure";
import { classify } from "./input";
import { presentation } from "./present";
import { fetchKeys, fetchReceipt, type Fetch, type PublishedKeys } from "./publish";
import { parseReceipt, ReceiptError, type Receipt } from "./receipt";
import { disclosedOf, GROUPS, verdictOf, verifyCertificate, verifyReceipt, type Group, type Status, type StepResult, type Trust } from "./verify";

/** The mounted explorer; each method is what its button does. */
export interface Explorer {
  ready: Promise<void>;
  verify(): Promise<void>;
  holderCopy(): Promise<void>;
  present(): Promise<void>;
}

const MARKS: Readonly<Record<Status, string>> = {
  pass: "PASS",
  fail: "FAIL",
  withheld: "WITHHELD",
  pending: "PENDING",
  unchecked: "NOT CHECKED",
};

const VERDICTS = {
  VERIFIED: "verified",
  "VERIFIED, FIELDS WITHHELD": "withheld",
  "NOT VERIFIED": "failed",
  INCOMPLETE: "incomplete",
  "CANNOT VERIFY": "error",
} as const;

const UNREACHABLE = "The server is unreachable; paste the receipt itself to verify offline";
const LOCAL_ONLY = "The holder copy is served only on the desk's own machine; paste it here instead";

function byId<T extends HTMLElement>(doc: Document, id: string): T {
  const el = doc.getElementById(id);
  if (el === null) throw new Error(`explorer: missing #${id}`);
  return el as T;
}

function element(doc: Document, tag: string, text: string, className?: string): HTMLElement {
  const el = doc.createElement(tag);
  if (className !== undefined) el.className = className;
  el.textContent = text;
  return el;
}

// Raw 32-byte key from standard base64, or null when the text is anything else.
function keyOf(text: string): Bytes | null {
  try {
    const key = fromBase64(text.trim());
    return key.length === 32 ? key : null;
  } catch {
    return null;
  }
}

/** Mounts the explorer on a page carrying explorer.html's ids; every receipt string is written as text. */
export function mountExplorer(doc: Document, fetchFn: Fetch): Explorer {
  const gateKey = byId<HTMLInputElement>(doc, "gate-key");
  const keySource = byId(doc, "key-source");
  const anonymity = byId(doc, "anonymity");
  const paste = byId<HTMLTextAreaElement>(doc, "paste");
  const verdict = byId(doc, "verdict");
  const steps = byId(doc, "steps");
  const reveals = byId(doc, "reveals");
  const output = byId<HTMLTextAreaElement>(doc, "presentation");

  let published: PublishedKeys | null = null;
  let pinned = false;
  // The last receipt verified and the payment id it was looked up by (null when pasted).
  let shown: Receipt | null = null;
  let lookedUp: string | null = null;
  // Each button press starts a run; a run that a later one superseded writes nothing.
  let runs = 0;

  byId(doc, "never").replaceChildren(...NEVER_IN_A_RECEIPT.map((line) => element(doc, "li", line)));

  function showVerdict(label: keyof typeof VERDICTS, text: string): void {
    verdict.dataset.verdict = VERDICTS[label];
    verdict.replaceChildren(element(doc, "span", label, "label"), element(doc, "span", text, "text"));
  }

  // A new run takes the last verdict down at once, so a pending lookup never sits under an old result.
  function start(): () => boolean {
    const ticket = ++runs;
    delete verdict.dataset.verdict;
    verdict.replaceChildren();
    steps.replaceChildren();
    reveals.replaceChildren();
    return () => ticket === runs;
  }

  function refuse(reason: string): void {
    showVerdict("CANNOT VERIFY", reason);
    steps.replaceChildren();
    reveals.replaceChildren();
  }

  function trust(): Trust | null {
    const key = keyOf(gateKey.value);
    if (key === null) return null;
    // The published holder list counts only for the key this server published, never for a hand-pinned one.
    const list = !pinned && published !== null && gateKey.value.trim() === published.gateKey ? published.holderKeys : null;
    const holderKeys = list?.map(keyOf).filter((k): k is Bytes => k !== null) ?? null;
    return { gateKey: key, holderKeys };
  }

  function showSteps(results: readonly StepResult[]): void {
    steps.replaceChildren(
      ...results.map((r) => {
        const li = doc.createElement("li");
        li.dataset.step = r.step;
        li.dataset.status = r.status;
        li.append(element(doc, "span", MARKS[r.status], "mark"), element(doc, "h3", r.step), element(doc, "p", r.detail));
        return li;
      }),
    );
    const { label, text } = verdictOf(results);
    showVerdict(label, text);
  }

  async function revealsOf(receipt: Receipt | null, results: readonly StepResult[], t: Trust): Promise<HTMLElement[]> {
    const disclosures = results.find((r) => r.step === "Receipt disclosures");
    if (receipt === null || disclosures?.status !== "pass") return [];
    const d = await disclosedOf(receipt, t.gateKey);
    if (d === null) return [];
    return exposure(receipt, d).flatMap(([term, value]) => {
      const row = [element(doc, "dt", term), element(doc, "dd", value)];
      // A withheld field reads as such in colour too, term and value alike.
      if (value === WITHHELD) for (const el of row) el.dataset.withheld = "";
      return row;
    });
  }

  // Verifies and shows `value`: the receipt it parsed to, or "superseded" when a later run took over and nothing was shown.
  async function check(value: unknown, t: Trust, current: () => boolean): Promise<Receipt | null | "superseded"> {
    let receipt: Receipt | null = null;
    try {
      receipt = parseReceipt(value);
    } catch (error) {
      if (!(error instanceof ReceiptError)) throw error;
    }
    const results = await verifyReceipt(value, t);
    const rows = await revealsOf(receipt, results, t);
    if (!current()) return "superseded";
    showSteps(results);
    reveals.replaceChildren(...rows);
    return receipt;
  }

  async function lookUp(id: string, t: Trust, full: boolean, current: () => boolean): Promise<void> {
    const found = await fetchReceipt(id, fetchFn, full);
    if (!current()) return;
    if (found === "offline") return refuse(UNREACHABLE);
    if (found === "not found") return refuse(`No receipt for ${id} on this server`);
    if (found === "local only") return refuse(LOCAL_ONLY);
    let answered: string | null = null;
    try {
      answered = parseReceipt(found.value).payment_id;
    } catch (error) {
      // A receipt that does not parse fails at Receipt format below.
      if (!(error instanceof ReceiptError)) throw error;
    }
    if (answered !== null && answered !== id) {
      return refuse(`The server answered with the receipt for ${answered}, not ${id}`);
    }
    const receipt = await check(found.value, t, current);
    if (receipt === "superseded") return;
    shown = receipt;
    lookedUp = id;
  }

  async function verify(): Promise<void> {
    const current = start();
    shown = null;
    lookedUp = null;
    const pasted = classify(paste.value);
    if (pasted.kind === "unknown") return refuse(pasted.reason);
    const t = trust();
    if (t === null) return refuse("The gate key must be 32 bytes of base64");
    switch (pasted.kind) {
      case "receipt": {
        const receipt = await check(pasted.value, t, current);
        if (receipt !== "superseded") shown = receipt;
        return;
      }
      case "certificate": {
        const results = await verifyCertificate(pasted.token, t);
        if (current()) showSteps(results);
        return;
      }
      case "payment":
        return lookUp(pasted.id, t, false, current);
      case "line":
        if (pasted.paymentId === null) return refuse(`Line #${pasted.seq} carries no payment receipt`);
        return lookUp(pasted.paymentId, t, false, current);
    }
  }

  async function holderCopy(): Promise<void> {
    const id = lookedUp;
    const current = start();
    if (id === null) return refuse("Look a payment up by its id first; the holder copy comes from this desk");
    const t = trust();
    if (t === null) return refuse("The gate key must be 32 bytes of base64");
    return lookUp(id, t, true, current);
  }

  async function present(): Promise<void> {
    const receipt = shown;
    const current = start();
    if (receipt === null) return refuse("Verify a receipt first");
    const t = trust();
    if (t === null) return refuse("The gate key must be 32 bytes of base64");
    const ticked = [...doc.querySelectorAll<HTMLInputElement>('#reveal input[name="reveal"]')]
      .filter((box) => box.checked && Object.hasOwn(GROUPS, box.value))
      .map((box) => box.value as Group);
    const copy = presentation(receipt, new Set(ticked));
    output.value = JSON.stringify(copy);
    await check(copy, t, current);
  }

  gateKey.addEventListener("input", () => {
    pinned = true;
    keySource.textContent = "Pinned by you";
    anonymity.textContent = anonymityText(null);
  });
  byId(doc, "verify").addEventListener("click", () => void verify());
  byId(doc, "holder-copy").addEventListener("click", () => void holderCopy());
  byId(doc, "present").addEventListener("click", () => void present());

  const ready = fetchKeys(fetchFn).then((keys) => {
    published = keys;
    // A key typed while the published one was loading stays the reader's own.
    if (pinned) return;
    anonymity.textContent = anonymityText(keys === null ? null : keys.holderKeys);
    if (keys === null) {
      keySource.textContent = "No key published here: paste the gate public key";
      return;
    }
    gateKey.value = keys.gateKey;
    keySource.textContent = "Published by this server";
  });

  return { ready, verify, holderCopy, present };
}
