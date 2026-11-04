import type { LineStore } from "../store/store";
import type { ConsoleLine } from "../wire/types";
import type { DeskApi, DeviceState } from "./api";
import {
  CONSENT_FIELDS,
  consentHash,
  formatAmount,
  groupHex,
  utcTime,
  type ConsentFields,
} from "./consent";
import { expiredAt, focusQuote, outcomeFor, type Phase } from "./state";

export const DEVICE_POLL_MS = 2000;
export const KNOWN_MAX = 64;
export const STEPS = [
  "Quoted",
  "Signed on the holder's device",
  "Checked at the gate",
  "Paid",
] as const;

export interface ApprovalOptions {
  now?: () => number;
  schedule?: (run: () => void, ms: number) => void;
  subtle?: SubtleCrypto | null;
}

type StepState = "done" | "current" | "todo" | "failed";

const STEP_STATES: Record<Phase, readonly StepState[]> = {
  waiting: ["done", "current", "todo", "todo"],
  refused: ["done", "failed", "todo", "todo"],
  expired: ["done", "failed", "todo", "todo"],
  approved: ["done", "done", "current", "todo"],
  paid: ["done", "done", "done", "done"],
  denied: ["done", "done", "failed", "todo"],
};

const NO_FIELDS = "Consent fields not seen by this console";
const UNAVAILABLE =
  "Consent hash unavailable here: needs a secure origin (https or localhost)";
const NO_CRYPTO = "Needs a secure origin (https or localhost)";

function node<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  parent: HTMLElement,
): HTMLElementTagNameMap[K] {
  const made = document.createElement(tag);
  made.className = className;
  parent.append(made);
  return made;
}

/** The one-line verdict for the status chip; the reason, if any, reads under the hash. */
function statusText(phase: Phase, paymentId: string | null, fields: ConsentFields | null): string {
  switch (phase) {
    case "waiting":
      return "Waiting for the holder";
    case "refused":
      return "Approval refused";
    case "expired":
      return fields === null ? "Expired before approval" : "Expired";
    case "approved":
      return "Signed on the holder's device. Waiting for the agent to confirm.";
    case "paid":
      return `Verified at the gate · paid ${paymentId ?? ""}`.trimEnd();
    case "denied":
      return "Denied at the gate";
    default: {
      const unreachable: never = phase;
      return unreachable;
    }
  }
}

function reasonText(phase: Phase, reason: string | null, fields: ConsentFields | null): string {
  switch (phase) {
    case "refused":
      return `${reason ?? "no reason given"}. Nothing moved; the quote is still open.`;
    case "expired":
      return fields === null
        ? ""
        : `Expired at ${utcTime(fields.expires_at)}. Approving now is refused.`;
    case "denied":
      return reason ?? "no reason given";
    case "waiting":
    case "approved":
    case "paid":
      return "";
    default: {
      const unreachable: never = phase;
      return unreachable;
    }
  }
}

function deviceText(replay: boolean, device: DeviceState | null): string {
  if (replay) return "Holder device not shown in replay";
  if (device === null) return "Holder device state unavailable";
  return device.paired
    ? `Holder device ${device.fingerprint ?? ""}`.trimEnd()
    : "No holder device paired yet";
}

function maxDeskSeq(lines: readonly ConsoleLine[]): number {
  let seq = 0;
  for (const line of lines) {
    switch (line.source) {
      case "desk":
        seq = Math.max(seq, line.seq);
        break;
      case "attack":
      case "hook":
      case "bill":
      case "deploy":
        break;
      default: {
        const unreachable: never = line;
        return unreachable;
      }
    }
  }
  return seq;
}

/** Builds the holder approval panel in `root`; it shows the consent and never signs. */
export function mountApproval(
  root: HTMLElement,
  store: LineStore,
  api: DeskApi | null,
  options: ApprovalOptions = {},
): { refresh(): Promise<void> } {
  const now = options.now ?? (() => Date.now());
  const schedule =
    options.schedule ??
    ((run: () => void, ms: number) => {
      setTimeout(run, ms);
    });
  const replay = api === null;

  const title = node("h2", "title", root);
  title.textContent = "Holder approval";
  title.tabIndex = 0;
  title.setAttribute("role", "button");
  const status = node("p", "status", root);
  status.setAttribute("role", "status");
  const stepList = node("ol", "steps", root);
  const stepNodes = STEPS.map((label) => {
    const item = node("li", "step", stepList);
    item.textContent = label;
    return item;
  });
  const amount = node("p", "amount", root);
  const payee = node("p", "payee", root);
  const fieldList = node("dl", "fields", root);
  const hashLabel = node("p", "hash-label", root);
  hashLabel.textContent = "Consent hash (sha256 of the signed bytes)";
  const hash = node("pre", "hash", root);
  const expires = node("p", "expires", root);
  const device = node("p", "device", root);
  const where = node("p", "where", root);
  where.textContent = "Approve on the holder's device. This console holds no key.";
  const gate = node("div", "gate", root);
  const check = node("p", "check", gate);
  const checkLabel = node("span", "label", check);
  const checkDigest = node("span", "digest", check);
  const reasonLine = node("p", "reason", gate);
  const deskError = node("p", "desk-error", root);
  deskError.textContent = "Desk unreachable; showing the last known state";
  deskError.hidden = true;
  root.hidden = true;

  const known = new Map<string, ConsentFields>();
  let pendingIds: string[] = [];
  let deviceState: DeviceState | null = null;
  let deskDown = false;
  let readSeq = 0;
  let pollScheduled = false;
  let renderTicket = 0;
  let shownPhase: Phase | null = null;
  let shownQuote = "";
  let opened = "";
  let readTicket = 0;

  function remember(id: string, fields: ConsentFields): void {
    known.delete(id);
    known.set(id, fields);
    while (known.size > KNOWN_MAX) {
      const oldest = known.keys().next().value;
      if (oldest === undefined) break;
      known.delete(oldest);
    }
  }

  async function readPending(): Promise<void> {
    if (api === null) return;
    const ticket = ++readTicket;
    readSeq = maxDeskSeq(store.lines());
    try {
      const quotes = await api.pending();
      if (ticket !== readTicket) return;
      for (const quote of quotes) remember(quote.quote_id, quote.consent);
      pendingIds = quotes.map((quote) => quote.quote_id);
      deskDown = false;
    } catch {
      if (ticket === readTicket) deskDown = true;
    }
  }

  async function readDevice(): Promise<void> {
    if (api === null || deviceState?.paired === true) return;
    try {
      deviceState = await api.device();
    } catch {
      deviceState = null;
    }
    if (deviceState?.paired !== true && !pollScheduled) {
      pollScheduled = true;
      schedule(() => {
        pollScheduled = false;
        void readDevice().then(render, () => undefined);
      }, DEVICE_POLL_MS);
    }
  }

  /** A paid or denied quote folds to its verdict line so the ledger under it stays reachable. */
  function syncFold(): void {
    const settled = shownPhase === "paid" || shownPhase === "denied";
    const folded = settled && opened !== shownQuote;
    if (folded) root.dataset.collapsed = "true";
    else delete root.dataset.collapsed;
    if (settled) title.setAttribute("aria-expanded", String(!folded));
    else title.removeAttribute("aria-expanded");
  }

  function toggleFold(): void {
    if (shownPhase !== "paid" && shownPhase !== "denied") return;
    opened = opened === shownQuote ? "" : shownQuote;
    syncFold();
  }

  title.addEventListener("click", toggleFold);
  title.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggleFold();
    }
  });

  async function render(): Promise<void> {
    const ticket = ++renderTicket;
    const lines = store.lines();
    const quote = focusQuote(lines, pendingIds);
    if (quote === null) {
      if (ticket === renderTicket) root.hidden = true;
      return;
    }
    const outcome = outcomeFor(lines, quote);
    const fields = known.get(quote) ?? outcome.gateConsent;
    let phase = outcome.phase;
    if (
      fields !== null &&
      (phase === "waiting" || phase === "refused") &&
      expiredAt(fields, now())
    ) {
      phase = "expired";
    }
    const shownHex = fields === null ? null : await consentHash(fields, options.subtle);
    const shownHash = fields === null ? "—" : shownHex === null ? NO_CRYPTO : groupHex(shownHex);
    let gateState: "match" | "mismatch" | "checked" | null = null;
    let gateLine = "";
    let gateDigest = "";
    const checkedFields = outcome.gateConsent;
    if (checkedFields !== null) {
      const gateHex = await consentHash(checkedFields, options.subtle);
      if (gateHex === null) {
        gateState = "checked";
        gateLine = UNAVAILABLE;
      } else if (fields === null || fields === checkedFields) {
        gateState = "checked";
        gateLine = "Gate checked consent hash: ";
        gateDigest = groupHex(gateHex);
      } else if (shownHex === null) {
        gateState = "checked";
        gateLine = UNAVAILABLE;
      } else if (shownHex === gateHex) {
        gateState = "match";
        gateLine = "Gate checked the same consent hash";
      } else {
        gateState = "mismatch";
        gateLine = "Gate checked a different consent hash: ";
        gateDigest = groupHex(gateHex);
      }
    }
    if (ticket !== renderTicket) return;

    root.hidden = false;
    root.dataset.phase = phase;
    root.dataset.quote = quote;
    shownPhase = phase;
    shownQuote = quote;
    syncFold();
    if (gateState === null) delete root.dataset.gate;
    else root.dataset.gate = gateState;
    status.textContent = statusText(phase, outcome.paymentId, fields);
    STEP_STATES[phase].forEach((state, i) => {
      (stepNodes[i] as HTMLElement).dataset.state = state;
    });
    amount.textContent = fields === null ? "—" : formatAmount(fields.amount_cents, fields.currency);
    payee.textContent = fields === null ? NO_FIELDS : `to ${fields.recipient}`;
    fieldList.replaceChildren();
    if (fields !== null) {
      for (const name of CONSENT_FIELDS) {
        const term = document.createElement("dt");
        term.textContent = name;
        const value = document.createElement("dd");
        value.textContent = String(fields[name]);
        fieldList.append(term, value);
      }
    }
    hash.textContent = shownHash;
    expires.textContent = fields === null ? "" : `Expires ${utcTime(fields.expires_at)}`;
    device.textContent = deviceText(replay, deviceState);
    checkLabel.textContent = gateLine;
    checkDigest.textContent = gateDigest;
    check.hidden = gateState === null;
    const why = reasonText(phase, outcome.reason, fields);
    reasonLine.textContent = why;
    reasonLine.hidden = why === "";
    gate.hidden = gateState === null && why === "";
    deskError.hidden = !deskDown;
  }

  async function refresh(): Promise<void> {
    await Promise.all([readPending(), readDevice()]);
    await render();
  }

  store.subscribe((lines) => {
    if (lines.length === 0) {
      known.clear();
      pendingIds = [];
      readSeq = 0;
    }
    if (api !== null && maxDeskSeq(lines) > readSeq) {
      void readPending().then(render, () => undefined);
    } else {
      void render();
    }
  });

  return { refresh };
}
