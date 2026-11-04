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
const VOICE_DOMAIN = "mandate/voice/v1";
export const VOICE_RATE = 24000;
export const VOICE_MAX_S = 15;

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

/** Hex sha256 of the consent bytes, the digest the gate checks. */
export async function consentHash(fields) {
  return hex(await crypto.subtle.digest("SHA-256", consentBytes(fields)));
}

/** First 16 hex of sha256 over a raw public key, to recognise this device. */
export async function fingerprint(rawKey) {
  return hex(await crypto.subtle.digest("SHA-256", rawKey)).slice(0, 16);
}

/** Lowercase hex in groups of eight, separated by one space. */
export function groupHex(digest) {
  return digest.match(/.{1,8}/g).join(" ");
}

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The seven consent fields as [name, text] pairs, in signed byte order. */
export function fieldRows(fields) {
  validate(fields);
  return FIELDS.map((name) => [name, String(fields[name])]);
}

/** Mono 16-bit PCM WAV of samples in [-1, 1], the format the desk accepts. */
export function encodeWav(samples, rate) {
  const view = new DataView(new ArrayBuffer(44 + samples.length * 2));
  const ascii = (offset, tag) => {
    for (let i = 0; i < tag.length; i += 1) view.setUint8(offset + i, tag.charCodeAt(i));
  };
  ascii(0, "RIFF");
  view.setUint32(4, 36 + samples.length * 2, true);
  ascii(8, "WAVE");
  ascii(12, "fmt ");
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, rate, true);
  view.setUint32(28, rate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  ascii(36, "data");
  view.setUint32(40, samples.length * 2, true);
  samples.forEach((sample, i) => {
    const s = Math.max(-1, Math.min(1, sample));
    view.setInt16(44 + i * 2, s < 0 ? s * 0x8000 : s * 0x7fff, true);
  });
  return new Uint8Array(view.buffer);
}

/** The line shown for what the transcriber heard. */
export function heardLine(text) {
  const words = text.trim();
  return words ? `You said: "${words}"` : "Nothing was heard.";
}

/** Why voice cannot work here, or null when it can. */
export function voiceSupport({ isSecureContext, mediaDevices, MediaRecorder }) {
  if (!isSecureContext) return "Voice needs a secure origin (https or localhost)";
  if (!mediaDevices || !MediaRecorder) return "Voice is not supported in this browser";
  return null;
}

/** Why voice is unavailable on this page, or null: browser support first, then the desk. */
export function voiceReason(support, voiceOn) {
  return support ?? (voiceOn ? null : "Voice is off on this desk");
}

/**
 * The page's voice line and control. Every write to the line is tied to the
 * quote it was started for, so words, progress and errors never sit beside
 * another quote's fields. `openMic()` resolves to `{start, stop, stopped, wav,
 * release}`; it is called only from a trusted tap and never when voice is off.
 */
export class VoiceUi {
  #o;
  #take = null;
  #speaking = false;

  constructor(options) {
    this.#o = { schedule: setTimeout, cancel: clearTimeout, ...options };
    if (this.#o.support !== null) {
      this.#o.speak.hidden = true;
      this.#o.speak.disabled = true;
      this.#o.heard.textContent = this.#o.support;
    }
  }

  #write(quote, text) {
    if (this.#o.approver.shownId === quote) this.#o.heard.textContent = text;
  }

  #idle() {
    const { speak, support, approver } = this.#o;
    speak.textContent = "Speak to confirm";
    speak.disabled = support !== null || !approver.shownId;
  }

  #stop() {
    if (!this.#take) return;
    this.#o.cancel(this.#take.timer);
    this.#o.speak.disabled = true;
    this.#take.mic.stop();
  }

  /** A quote is now shown: drop any take or line that belongs to another. */
  quoteShown() {
    const { heard, speak, support, approver } = this.#o;
    if (this.#take && this.#take.quote !== approver.shownId) this.#stop();
    if (!this.#take) heard.textContent = support ?? "";
    else if (this.#take.quote !== approver.shownId) heard.textContent = "";
    if (support === null && !this.#speaking) speak.disabled = false;
  }

  /** No quote is shown any more. */
  cleared() {
    this.#stop();
    this.#o.heard.textContent = this.#o.support ?? "";
    this.#o.speak.disabled = true;
  }

  async click() {
    if (this.#o.support !== null) return;
    if (this.#take) this.#stop();
    else await this.#record();
  }

  async #record() {
    const { approver, speak, heard, api, keys, openMic, schedule, cancel } = this.#o;
    const quote = approver.shownId;
    if (!quote || this.#speaking) return;
    this.#speaking = true;
    speak.disabled = true;
    let mic;
    try {
      mic = await openMic();
    } catch (error) {
      this.#write(quote, `Microphone refused: ${error.message}`);
      this.#speaking = false;
      this.#idle();
      return;
    }
    try {
      // The holder moved on while the permission prompt was open.
      if (approver.shownId !== quote) return;
      const timer = schedule(() => this.#stop(), VOICE_MAX_S * 1000);
      this.#take = { mic, quote, timer };
      mic.start();
      speak.textContent = "Stop";
      speak.disabled = false;
      heard.textContent = "Listening. Tap Stop when done.";
      await mic.stopped;
      this.#take = null;
      cancel(timer);
      speak.textContent = "Speak to confirm";
      // A clip for a quote no longer shown is dropped, not spent on the model.
      if (approver.shownId !== quote) return;
      heard.textContent = "Transcribing.";
      const wav = await mic.wav();
      const signature = await (this.#o.sign ?? signVoice)(keys, quote, wav);
      const words = await api.transcribe(quote, wav, signature);
      this.#write(quote, heardLine(words));
    } catch (error) {
      this.#write(quote, error.message);
    } finally {
      mic.release();
      this.#take = null;
      this.#speaking = false;
      this.#idle();
    }
  }
}

/** Bytes the paired key signs to upload a clip; twin of the desk's voice_bytes. */
export async function voiceBytes(quoteId, wav) {
  const digest = hex(await crypto.subtle.digest("SHA-256", wav));
  return new TextEncoder().encode(`${VOICE_DOMAIN}\n${quoteId}\n${digest}`);
}

/** Unpadded base64url Ed25519 signature of a clip with the paired holder key. */
export async function signVoice(keys, quoteId, wav) {
  const bytes = await voiceBytes(quoteId, wav);
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, keys.privateKey, bytes);
  return toBase64(signature).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Bytes the holder key signs to certify a one-time consent key for one nonce. */
export function keyBytes(consentKey, nonce) {
  const sized = consentKey instanceof Uint8Array && consentKey.length === 32;
  if (!sized || typeof nonce !== "string" || !PRINTABLE.test(nonce)) {
    throw malformed();
  }
  const body = JSON.stringify({ consent_key: toBase64(consentKey), nonce });
  return new TextEncoder().encode(`consent-key/v1:${body}`);
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
  async function transcribe(quoteId, wav, signature) {
    const response = await fetchFn(
      `${base}/api/voice?quote=${encodeURIComponent(quoteId)}`,
      {
        method: "POST",
        headers: { "content-type": "audio/wav", "x-mandate-voice-sig": signature },
        body: wav,
      },
    );
    const body = (await response.json().catch(() => null)) ?? {};
    if (!response.ok) {
      throw new Error(`Voice refused: ${body.reason ?? body.error ?? response.status}`);
    }
    if (typeof body.transcript !== "string") {
      throw new Error("Voice refused: malformed answer");
    }
    return body.transcript;
  }
  async function voiceOn() {
    try {
      return (await call("/api/device")).voice === true;
    } catch {
      return false;
    }
  }
  return {
    transcribe,
    voiceOn,
    pending: async () => (await call("/api/pending")).pending,
    approve: (quoteId, approval) =>
      call("/api/approve", { quote_id: quoteId, ...approval }),
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

const ED25519 = { name: "Ed25519" };

/**
 * Signs the consent with a key drawn for it alone and certifies that key with
 * the holder key, so no two receipts carry the same key.
 */
export async function oneTimeApproval(holderPrivateKey, bytes, nonce) {
  const oneTime = await crypto.subtle.generateKey(ED25519, false, ["sign"]);
  const consentKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", oneTime.publicKey),
  );
  const [signature, keySignature] = await Promise.all([
    crypto.subtle.sign(ED25519, oneTime.privateKey, bytes),
    crypto.subtle.sign(ED25519, holderPrivateKey, keyBytes(consentKey, nonce)),
  ]);
  return {
    signature: toBase64(signature),
    consent_key: toBase64(consentKey),
    key_signature: toBase64(keySignature),
  };
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
    this.#render(line, quote.consent);
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
      const approval = await oneTimeApproval(
        this.#keys.privateKey,
        bytes,
        shown.consent.nonce,
      );
      const result = await this.#api.approve(shown.quote_id, approval);
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
  let ticket = 0;
  const support = voiceReason(
    voiceSupport({
      isSecureContext: window.isSecureContext,
      mediaDevices: navigator.mediaDevices,
      MediaRecorder: window.MediaRecorder,
    }),
    await api.voiceOn(),
  );
  const showFields = (consent) => {
    const cells = fieldRows(consent).flatMap(([name, value]) => {
      const term = document.createElement("dt");
      term.textContent = name;
      const detail = document.createElement("dd");
      detail.textContent = value;
      return [term, detail];
    });
    $("fields").replaceChildren(...cells);
  };
  const approver = new Approver(api, keys, (line, consent) => {
    $("shown").textContent = line;
    $("approve").disabled = false;
    showFields(consent);
    voice.quoteShown();
    const mine = ++ticket;
    consentHash(consent).then((digest) => {
      if (mine === ticket) $("hash").textContent = `Consent hash ${groupHex(digest)}`;
    }, () => {});
  });
  const clearHash = () => {
    ticket += 1;
    $("hash").textContent = "";
  };
  // The browser records at its own rate and codec, typically 48 kHz webm/opus,
  // which the desk refuses; re-render to mono 16-bit at VOICE_RATE.
  async function toWav(blob) {
    const context = new AudioContext();
    let decoded;
    try {
      decoded = await context.decodeAudioData(await blob.arrayBuffer());
    } finally {
      context.close();
    }
    const frames = Math.ceil(decoded.duration * VOICE_RATE);
    const offline = new OfflineAudioContext(1, frames, VOICE_RATE);
    const source = offline.createBufferSource();
    source.buffer = decoded;
    source.connect(offline.destination);
    source.start();
    const rendered = await offline.startRendering();
    return encodeWav(rendered.getChannelData(0), VOICE_RATE);
  }

  async function openMic() {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: { channelCount: 1 },
    });
    const recorder = new MediaRecorder(stream);
    const chunks = [];
    recorder.addEventListener("dataavailable", (event) => {
      if (event.data.size) chunks.push(event.data);
    });
    const release = () => {
      for (const track of stream.getTracks()) track.stop();
    };
    const stopped = new Promise((resolve) => {
      recorder.addEventListener("stop", resolve, { once: true });
    }).then(release);
    return {
      start: () => recorder.start(),
      stop: () => {
        if (recorder.state !== "inactive") recorder.stop();
      },
      stopped,
      wav: () => toWav(new Blob(chunks, { type: recorder.mimeType })),
      release,
    };
  }
  const voice = new VoiceUi({
    heard: $("heard"),
    speak: $("speak"),
    approver,
    keys,
    api,
    support,
    openMic,
  });

  const clearVoice = () => {
    $("fields").replaceChildren();
    voice.cleared();
  };

  // The microphone opens only from the holder's own tap, never from a script.
  $("speak").addEventListener("click", (event) => {
    if (event.isTrusted) voice.click();
  });
  const fail = (error) => {
    $("status").textContent = error.message;
  };

  async function refresh() {
    const quotes = await api.pending();
    if (approver.forget(quotes.map((q) => q.quote_id))) {
      $("shown").textContent = "";
      clearHash();
      clearVoice();
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
      clearHash();
      clearVoice();
      await refresh();
    } catch (error) {
      fail(error);
      if (approver.shownId) $("approve").disabled = false;
    }
  });

  const raw = await crypto.subtle.exportKey("raw", keys.publicKey);
  $("device").textContent = `This device ${await fingerprint(raw)}`;
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
