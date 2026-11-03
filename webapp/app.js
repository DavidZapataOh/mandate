const FIELDS = [
  "amount_cents",
  "currency",
  "expires_at",
  "nonce",
  "recipient",
  "reference",
  "source",
];
const TEXT_FIELDS = ["currency", "nonce", "recipient", "reference", "source"];
const PRINTABLE = /^[\x21-\x7e]+$/;

function malformed() {
  return new Error("consent: malformed");
}

function validate(fields) {
  if (fields === null || typeof fields !== "object") throw malformed();
  for (const name of TEXT_FIELDS) {
    const value = fields[name];
    if (typeof value !== "string" || !PRINTABLE.test(value)) throw malformed();
  }
  const { amount_cents: amount, expires_at: expires } = fields;
  if (!Number.isSafeInteger(amount) || amount <= 0) throw malformed();
  if (!Number.isSafeInteger(expires) || expires < 0) throw malformed();
}

/** Canonical bytes the gate verifies; must stay identical to its Python twin. */
export function consentBytes(fields) {
  validate(fields);
  const ordered = {};
  for (const name of FIELDS) ordered[name] = fields[name];
  return new TextEncoder().encode(`consent/v1:${JSON.stringify(ordered)}`);
}

export function describe(fields) {
  validate(fields);
  const cents = fields.amount_cents;
  const amount = `${Math.floor(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
  return (
    `Pay ${amount} ${fields.currency} to ${fields.recipient} ` +
    `(ref ${fields.reference}) from ${fields.source}`
  );
}

function toBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

export function httpApi(base, fetchFn = fetch) {
  async function call(path, body) {
    const init = body
      ? {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        }
      : {};
    const response = await fetchFn(`${base}${path}`, init);
    if (!response.ok) throw new Error(`desk error ${response.status}`);
    return response.json();
  }
  return {
    pending: async () => (await call("/api/pending")).pending,
    approve: (quoteId, signature) =>
      call("/api/approve", { quote_id: quoteId, signature }),
    registerHolder: (publicKey, pairing) =>
      call("/api/holder", { public_key: publicKey, pairing }),
  };
}

/**
 * Registers the holder key when the URL fragment carries the desk's pairing token.
 * Returns a status line, or null when there is nothing to pair.
 */
export async function pair(api, publicKey, hash) {
  const token = new URLSearchParams(hash.replace(/^#/, "")).get("pair");
  if (!token) return null;
  const { registered } = await api.registerHolder(publicKey, token);
  return registered
    ? "Paired with the desk."
    : "Another holder is already paired; " +
        "approvals from this device will be refused.";
}

export async function holderKey(store) {
  const saved = await store.load();
  if (saved) return saved;
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ]);
  await store.save(pair);
  return pair;
}

export class Approver {
  #api;
  #keys;
  #render;
  #shown = null;
  #busy = false;

  constructor(api, keys, render) {
    this.#api = api;
    this.#keys = keys;
    this.#render = render;
  }

  async pending() {
    const quotes = await this.#api.pending();
    if (quotes.length === 0) return "No pending payments.";
    return quotes.map((q) => `${q.quote_id}: ${describe(q.consent)}`).join("\n");
  }

  get shownId() {
    return this.#shown?.quote_id ?? null;
  }

  /** Drops the shown quote when it is no longer pending; true if one was dropped. */
  forget(pendingIds) {
    if (this.#busy || !this.#shown || pendingIds.includes(this.#shown.quote_id)) {
      return false;
    }
    this.#shown = null;
    return true;
  }

  // Shows only: signing is reserved for approve(), reached from the Approve tap.
  async review(quoteId) {
    if (this.#busy) throw new Error("approval in progress");
    const quote = (await this.#api.pending()).find((q) => q.quote_id === quoteId);
    if (!quote) throw new Error(`no pending quote ${quoteId}`);
    const line = describe(quote.consent);
    this.#shown = quote;
    this.#render(line);
    return `${line}. Tap Approve on the display to sign.`;
  }

  async approve() {
    if (this.#busy) throw new Error("approval in progress");
    const shown = this.#shown;
    if (!shown) throw new Error("nothing to approve");
    this.#busy = true;
    try {
      // Sign what the page rebuilds from the fields it displayed, not a server summary.
      const bytes = consentBytes(shown.consent);
      const signature = await crypto.subtle.sign(
        { name: "Ed25519" },
        this.#keys.privateKey,
        bytes,
      );
      const result = await this.#api.approve(shown.quote_id, toBase64(signature));
      if (result.status !== "approved") {
        throw new Error(`approval refused: ${result.reason ?? result.status}`);
      }
      if (this.#shown === shown) this.#shown = null;
      return result;
    } finally {
      this.#busy = false;
    }
  }
}

function text(value) {
  return { content: [{ type: "text", text: value }] };
}

export function registerTools(modelContext, approver) {
  modelContext.registerTool({
    name: "get_pending_payment",
    description: "List payments awaiting the account holder's approval.",
    inputSchema: { type: "object", properties: {} },
    annotations: { readOnlyHint: true },
    execute: async () => text(await approver.pending()),
  });
  modelContext.registerTool({
    name: "review_payment",
    description:
      "Show a pending payment on the display. This does not approve it; " +
      "the account holder taps Approve on the display.",
    inputSchema: {
      type: "object",
      properties: { quote_id: { type: "string" } },
      required: ["quote_id"],
    },
    execute: async ({ quote_id: quoteId }) => text(await approver.review(quoteId)),
  });
}

const DB = "mandate-holder";
const STORE = "keys";
const SLOT = "holder";

function idbRequest(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function indexedDbStore() {
  const open = indexedDB.open(DB, 1);
  open.onupgradeneeded = () => open.result.createObjectStore(STORE);
  const db = await idbRequest(open);
  const objects = (mode) => db.transaction(STORE, mode).objectStore(STORE);
  return {
    load: async () => (await idbRequest(objects("readonly").get(SLOT))) ?? null,
    save: async (pair) => {
      await idbRequest(objects("readwrite").put(pair, SLOT));
    },
  };
}

async function boot() {
  const $ = (id) => document.getElementById(id);
  const keys = await holderKey(await indexedDbStore());
  const api = httpApi(location.origin);
  const approver = new Approver(api, keys, (line) => {
    $("shown").textContent = line;
    $("approve").disabled = false;
  });
  const fail = (error) => {
    $("status").textContent = error.message;
  };

  async function refresh() {
    const quotes = await api.pending();
    if (approver.forget(quotes.map((q) => q.quote_id))) {
      $("shown").textContent = "";
      $("approve").disabled = true;
    }
    const list = $("quotes");
    list.replaceChildren();
    $("status").textContent = quotes.length ? "" : "No pending payments.";
    for (const quote of quotes) {
      const item = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = describe(quote.consent);
      const button = document.createElement("button");
      button.textContent = "Review";
      button.addEventListener("click", () => {
        approver.review(quote.quote_id).catch(fail);
      });
      item.append(label, button);
      list.append(item);
    }
  }

  $("approve").addEventListener("click", async (event) => {
    if (!event.isTrusted) return;
    $("approve").disabled = true;
    try {
      await approver.approve();
      $("shown").textContent = "Approved.";
      await refresh();
    } catch (error) {
      fail(error);
      if (approver.shownId) $("approve").disabled = false;
    }
  });

  const raw = await crypto.subtle.exportKey("raw", keys.publicKey);
  const hash = location.hash;
  // The token is single-use; drop it from the address bar and history.
  if (hash) history.replaceState(null, "", location.pathname + location.search);
  try {
    const note = await pair(api, toBase64(raw), hash);
    if (note) $("pairing").textContent = note;
  } catch (error) {
    $("pairing").textContent = `Pairing refused: ${error.message}`;
  }
  if (document.modelContext) registerTools(document.modelContext, approver);
  await refresh();
  setInterval(() => refresh().catch(fail), 5000);
}

if (typeof document !== "undefined") {
  boot().catch((error) => {
    const status = document.getElementById("status");
    status.textContent = `Startup failed: ${error.message}`;
  });
}
