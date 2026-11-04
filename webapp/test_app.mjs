import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  Approver,
  VoiceUi,
  consentBytes,
  consentHash,
  describe,
  encodeWav,
  fieldRows,
  fingerprint,
  groupHex,
  heardLine,
  holderKey,
  httpApi,
  keyBytes,
  oneTimeApproval,
  pair,
  registerTools,
  signVoice,
  unpairBytes,
  unpairDevice,
  voiceBytes,
  voiceReason,
  voiceSupport,
} from "./app.js";

const GOLDEN =
  'consent/v1:{"amount_cents":20000,"currency":"USD","expires_at":1800001600,' +
  '"nonce":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0","recipient":"acme-991",' +
  '"reference":"A-991","source":"checking-881"}';
const FIELDS = {
  amount_cents: 20000,
  currency: "USD",
  expires_at: 1800001600,
  nonce: "c0".repeat(16),
  recipient: "acme-991",
  reference: "A-991",
  source: "checking-881",
};
const CONSENT_KEY = "k9ufLuD3456UL7WUQRkL8gucQ8/MigUaFSSZzzkrejc=";
const KEY_GOLDEN =
  'consent-key/v1:{"consent_key":"k9ufLuD3456UL7WUQRkL8gucQ8/MigUaFSSZzzkrejc=",' +
  '"nonce":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"}';
const LINE = "Pay 200.00 USD to acme-991 (ref A-991) from checking-881";
const ED = { name: "Ed25519" };
const SIGNAL = { signal: AbortSignal.timeout(10000) };

function memoryStore() {
  let saved = null;
  return {
    load: async () => saved,
    save: async (pair) => {
      saved = pair;
    },
    forget: async () => {
      saved = null;
    },
  };
}

// PKCS#8 wrapper of the Ed25519 seed 0x02 * 32 (the gate tests' holder seed).
const HOLDER_PKCS8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  Buffer.alloc(32, 2),
]);
const HOLDER_KEY = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";
const UNPAIR_SIGNATURE =
  "funkeiu1a6bTgwfybxQ+sD+Tvsvj6VueGAKqTooc1JBkljz9IoPavw+Eu/IMakx/TR9A18oGGuhY/eYM" +
  "gdzZBA==";

async function seededKeys() {
  const privateKey = await crypto.subtle.importKey("pkcs8", HOLDER_PKCS8, ED, false, [
    "sign",
  ]);
  const raw = Buffer.from(HOLDER_KEY, "base64");
  const publicKey = await crypto.subtle.importKey("raw", raw, ED, true, ["verify"]);
  return { privateKey, publicKey };
}

function fakeApi(pending) {
  const approvals = [];
  return {
    approvals,
    pending: async () => pending,
    approve: async (quoteId, approval) => {
      approvals.push({ quoteId, ...approval });
      return { status: "approved", quote_id: quoteId };
    },
  };
}

function gated(api) {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const approve = api.approve;
  api.approve = async (...args) => {
    await gate;
    return approve(...args);
  };
  return release;
}

async function tools(api, render = () => {}) {
  const seen = [];
  const approver = new Approver(api, await holderKey(memoryStore()), render);
  registerTools({ registerTool: (tool) => seen.push(tool) }, approver);
  return { seen, approver };
}

test("consent bytes match the gate golden", () => {
  assert.equal(new TextDecoder().decode(consentBytes(FIELDS)), GOLDEN);
});

test("consent bytes reject non-ASCII fields", () => {
  const bad = { ...FIELDS, recipient: "acmé" };
  assert.throws(() => consentBytes(bad), /consent: malformed/);
});

test("consent hash is the gate's sha256, grouped in eights", async () => {
  assert.equal(
    groupHex(await consentHash(FIELDS)),
    "a3a19e2b 9de9b033 42451a42 d2fdbc06 d4281d50 f9ba2785 362ba8db 2b024ac7",
  );
});

test("fingerprint is the first 16 hex of sha256 over the raw key", async () => {
  const raw = Uint8Array.from({ length: 32 }, (_, i) => i);
  assert.equal(await fingerprint(raw), "630dcd2966c43366");
});

test("review hands the display the consent fields it shows", async () => {
  const api = fakeApi([{ quote_id: "q:000001", consent: FIELDS }]);
  const shown = [];
  const { approver } = await tools(api, (line, consent) => shown.push([line, consent]));
  await approver.review("q:000001");
  assert.deepEqual(shown, [[LINE, FIELDS]]);
});

const PAGE_WAV =
  "524946462c00000057415645666d74201000000001000100c05d000080bb0000" +
  "0200100064617461080000000000ff3f0080ff7f";
const hex = (bytes) => Buffer.from(bytes).toString("hex");

test("the page encodes speech as the mono 16-bit 24 kHz WAV the desk accepts", () => {
  assert.equal(hex(encodeWav(Float32Array.of(0, 0.5, -1, 1), 24000)), PAGE_WAV);
});

test("samples past full scale are clipped, not wrapped", () => {
  const wav = encodeWav(Float32Array.of(1.03, -2), 24000);
  assert.equal(hex(wav.subarray(44)), "ff7f0080");
});

test("voice posts the raw clip for the shown quote, returns only the words", async () => {
  const sent = [];
  const fetchFn = async (url, init) => {
    sent.push([url, init.method, init.headers, init.body]);
    return { ok: true, status: 200, json: async () => ({ transcript: "Pay Acme" }) };
  };
  const wav = encodeWav(new Float32Array(16), 24000);
  const api = httpApi("http://desk", fetchFn);
  assert.equal(await api.transcribe("q:000001", wav, "SIG"), "Pay Acme");
  const headers = { "content-type": "audio/wav", "x-mandate-voice-sig": "SIG" };
  assert.deepEqual(sent, [
    ["http://desk/api/voice?quote=q%3A000001", "POST", headers, wav],
  ]);
});

const VOICE_SIGNED =
  "mandate/voice/v1\nq:000001\n" +
  "51758465b504b589a7d1b54e6c134af376c6a98482f803b8b5e57d76e461bfe5";

test("a clip is signed with the paired key over its quote and its sha256", async () => {
  const wav = Uint8Array.from(Buffer.from(PAGE_WAV, "hex"));
  const bytes = await voiceBytes("q:000001", wav);
  assert.equal(new TextDecoder().decode(bytes), VOICE_SIGNED);
  const keys = await holderKey(memoryStore());
  const token = await signVoice(keys, "q:000001", wav);
  assert.match(token, /^[A-Za-z0-9_-]{86}$/);
  const sig = Buffer.from(token, "base64url");
  const signed = new TextEncoder().encode(VOICE_SIGNED);
  assert.equal(await crypto.subtle.verify(ED, keys.publicKey, sig, signed), true);
});

test("a refused clip surfaces the desk's reason", async () => {
  const reason = "voice off: start the desk with --voice";
  const fetchFn = async () => ({
    ok: false,
    status: 503,
    json: async () => ({ error: "voice unavailable", reason }),
  });
  const api = httpApi("http://desk", fetchFn);
  await assert.rejects(api.transcribe("q:000001", new Uint8Array(44), "SIG"), {
    message: `Voice refused: ${reason}`,
  });
});

test("the seven consent fields are listed in signed order", () => {
  const reversed = Object.fromEntries(Object.entries(FIELDS).reverse());
  assert.deepEqual(fieldRows(reversed), [
    ["amount_cents", "20000"],
    ["currency", "USD"],
    ["expires_at", "1800001600"],
    ["nonce", "c0".repeat(16)],
    ["recipient", "acme-991"],
    ["reference", "A-991"],
    ["source", "checking-881"],
  ]);
});

test("heard words are quoted as said, and silence is named", () => {
  assert.equal(heardLine(" Pay <b>Acme</b> "), 'You said: "Pay <b>Acme</b>"');
  assert.equal(heardLine("  "), "Nothing was heard.");
});

test("voice is offered only where the microphone can work", () => {
  const ok = { isSecureContext: true, mediaDevices: {}, MediaRecorder: class {} };
  assert.equal(voiceSupport(ok), null);
  assert.equal(
    voiceSupport({ ...ok, isSecureContext: false }),
    "Voice needs a secure origin (https or localhost)",
  );
  assert.equal(
    voiceSupport({ ...ok, MediaRecorder: undefined }),
    "Voice is not supported in this browser",
  );
});

test("the page writes untrusted text only as text", async () => {
  const source = await readFile(new URL("./app.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
});

test("key bytes match the gate golden", () => {
  const key = new Uint8Array(Buffer.from(CONSENT_KEY, "base64"));
  assert.equal(new TextDecoder().decode(keyBytes(key, "c0".repeat(16))), KEY_GOLDEN);
});

test("key bytes reject a short key or a spaced nonce", () => {
  const key = new Uint8Array(Buffer.from(CONSENT_KEY, "base64"));
  assert.throws(() => keyBytes(key.slice(1), "c0".repeat(16)), /consent: malformed/);
  assert.throws(() => keyBytes(key, "c0 c0"), /consent: malformed/);
});

test("describe matches the desk summary", () => {
  assert.equal(describe(FIELDS), LINE);
});

test("tools registered for the glasses assistant", async () => {
  const { seen } = await tools(fakeApi([]));
  assert.deepEqual(
    seen.map((t) => t.name),
    ["get_pending_payment", "review_payment"],
  );
  assert.equal(seen[0].annotations.readOnlyHint, true);
  assert.deepEqual(seen[1].inputSchema, {
    type: "object",
    properties: { quote_id: { type: "string" } },
    required: ["quote_id"],
  });
});

test("pending lines are built from consent fields", async () => {
  const quote = { quote_id: "q:000001", consent: FIELDS, summary: "ignored" };
  const { seen } = await tools(fakeApi([quote]));
  const out = await seen[0].execute({}, SIGNAL);
  assert.equal(out.content[0].text, `q:000001: ${LINE}`);
});

test("review never signs; only approve does", async () => {
  const api = fakeApi([{ quote_id: "q:000001", consent: FIELDS }]);
  const shown = [];
  const { seen, approver } = await tools(api, (text) => shown.push(text));
  const out = await seen[1].execute({ quote_id: "q:000001" }, SIGNAL);
  assert.equal(api.approvals.length, 0);
  assert.equal(out.content[0].text, `${LINE}. Tap Approve on the display to sign.`);
  assert.deepEqual(shown, [LINE]);
  assert.equal((await approver.approve()).status, "approved");
  assert.equal(api.approvals.length, 1);
});

test("page signs bytes it rebuilds from the consent fields", async () => {
  const evil = { ...FIELDS, recipient: "evil-666" };
  const api = fakeApi([{ quote_id: "q:000001", consent: evil, summary: LINE }]);
  const keys = await holderKey(memoryStore());
  const approver = new Approver(api, keys, () => {});
  const text = await approver.review("q:000001");
  assert.match(text, /evil-666/);
  assert.doesNotMatch(text, /acme-991/);
  await approver.approve();
  const sent = api.approvals[0];
  const sig = Buffer.from(sent.signature, "base64");
  const raw = Buffer.from(sent.consent_key, "base64");
  const consentKey = await crypto.subtle.importKey("raw", raw, ED, true, ["verify"]);
  const verify = (fields) =>
    crypto.subtle.verify(ED, consentKey, sig, consentBytes(fields));
  assert.equal(await verify(evil), true);
  assert.equal(await verify(FIELDS), false);
});

test("each approval signs with a fresh key the holder key certifies", async () => {
  const keys = await holderKey(memoryStore());
  const holderRaw = Buffer.from(await crypto.subtle.exportKey("raw", keys.publicKey));
  const bytes = consentBytes(FIELDS);
  const first = await oneTimeApproval(keys.privateKey, bytes, FIELDS.nonce);
  const second = await oneTimeApproval(keys.privateKey, bytes, FIELDS.nonce);
  assert.notEqual(first.consent_key, second.consent_key);
  for (const sent of [first, second]) {
    const raw = Buffer.from(sent.consent_key, "base64");
    assert.notDeepEqual(raw, holderRaw);
    const oneTime = await crypto.subtle.importKey("raw", raw, ED, true, ["verify"]);
    const certified = keyBytes(new Uint8Array(raw), FIELDS.nonce);
    const keySig = Buffer.from(sent.key_signature, "base64");
    const sig = Buffer.from(sent.signature, "base64");
    const holderSigned = crypto.subtle.verify(ED, keys.publicKey, keySig, certified);
    assert.equal(await holderSigned, true);
    assert.equal(await crypto.subtle.verify(ED, oneTime, sig, bytes), true);
    assert.equal(await crypto.subtle.verify(ED, keys.publicKey, sig, bytes), false);
  }
});

test("the one-time private key is non-extractable and never kept", async () => {
  const generated = [];
  const original = crypto.subtle.generateKey.bind(crypto.subtle);
  let saves = 0;
  let saved = null;
  const store = {
    load: async () => saved,
    save: async (pair) => {
      saves += 1;
      saved = pair;
    },
  };
  const keys = await holderKey(store);
  const pending = [{ quote_id: "q:000001", consent: FIELDS }];
  const api = fakeApi(pending);
  const approver = new Approver(api, keys, () => {});
  crypto.subtle.generateKey = async (...args) => {
    const made = await original(...args);
    generated.push(made);
    return made;
  };
  try {
    await approver.review("q:000001");
    await approver.approve();
  } finally {
    crypto.subtle.generateKey = original;
  }
  assert.equal(generated.length, 1);
  assert.equal(generated[0].privateKey.extractable, false);
  assert.equal(saves, 1);
  assert.notEqual(saved.privateKey, generated[0].privateKey);
  for (const value of Object.values(api.approvals[0])) {
    assert.equal(typeof value, "string");
  }
  for (const holder of [approver, ...Object.values(approver)]) {
    assert.ok(!Object.values(holder ?? {}).includes(generated[0].privateKey));
  }
});

test("approve posts the one-time key and its certificate", async () => {
  const sent = [];
  const fetchFn = async (url, init) => {
    sent.push([url, JSON.parse(init.body)]);
    return { ok: true, json: async () => ({ status: "approved" }) };
  };
  const approval = { signature: "S", consent_key: "K", key_signature: "C" };
  await httpApi("http://desk", fetchFn).approve("q:000001", approval);
  assert.deepEqual(sent, [
    [
      "http://desk/api/approve",
      { quote_id: "q:000001", signature: "S", consent_key: "K", key_signature: "C" },
    ],
  ]);
});

test("approve with nothing shown is refused", async () => {
  const { approver } = await tools(fakeApi([]));
  await assert.rejects(approver.approve(), /nothing to approve/);
});

test("review of an unknown quote throws", async () => {
  const { seen } = await tools(fakeApi([]));
  await assert.rejects(
    seen[1].execute({ quote_id: "q:000009" }, SIGNAL),
    /no pending quote q:000009/,
  );
});

test("holder key is created once, private part not extractable", async () => {
  const store = memoryStore();
  const first = await holderKey(store);
  assert.equal(await holderKey(store), first);
  assert.equal(first.privateKey.extractable, false);
});

test("concurrent approve taps sign and send once", async () => {
  const api = fakeApi([{ quote_id: "q:000001", consent: FIELDS }]);
  const release = gated(api);
  const { approver } = await tools(api);
  await approver.review("q:000001");
  const first = approver.approve();
  await assert.rejects(approver.approve(), /approval in progress/);
  release();
  assert.equal((await first).status, "approved");
  assert.equal(api.approvals.length, 1);
});

test("review is refused while an approval is in flight", async () => {
  const api = fakeApi([{ quote_id: "q:000001", consent: FIELDS }]);
  const release = gated(api);
  const { approver } = await tools(api);
  await approver.review("q:000001");
  const first = approver.approve();
  await assert.rejects(approver.review("q:000001"), /approval in progress/);
  release();
  await first;
  assert.equal(approver.shownId, null);
});

test("forget drops a shown quote that left pending", async () => {
  const api = fakeApi([{ quote_id: "q:000001", consent: FIELDS }]);
  const { approver } = await tools(api);
  await approver.review("q:000001");
  assert.equal(approver.forget(["q:000001"]), false);
  assert.equal(approver.shownId, "q:000001");
  assert.equal(approver.forget([]), true);
  assert.equal(approver.shownId, null);
  await assert.rejects(approver.approve(), /nothing to approve/);
});

test("pair registers only with a token from the fragment", async () => {
  const calls = [];
  const api = {
    registerHolder: async (key, token) => {
      calls.push([key, token]);
      return { registered: calls.length === 1 };
    },
  };
  assert.equal(await pair(api, "KEY", ""), null);
  assert.equal(await pair(api, "KEY", "#other=1"), null);
  assert.match(await pair(api, "KEY", "#pair=tok-1"), /^Paired/);
  assert.equal(
    await pair(api, "KEY", "#pair=tok-2"),
    "Not paired: this device's key paired with the desk before, " +
      "or every holder slot is taken.",
  );
  assert.deepEqual(calls, [
    ["KEY", "tok-1"],
    ["KEY", "tok-2"],
  ]);
});

test("unpair bytes and signature match the gate golden", async () => {
  const raw = new Uint8Array(Buffer.from(HOLDER_KEY, "base64"));
  assert.equal(
    new TextDecoder().decode(unpairBytes(raw)),
    `holder-unpair/v1:${HOLDER_KEY}`,
  );
  const sent = [];
  const api = {
    unpair: async (publicKey, signature) => {
      sent.push([publicKey, signature]);
      return { unpaired: true };
    },
  };
  await unpairDevice(api, await seededKeys(), memoryStore());
  assert.deepEqual(sent, [[HOLDER_KEY, UNPAIR_SIGNATURE]]);
});

test("an unpaired device forgets its key; a refused one keeps it", async () => {
  for (const [unpaired, note, kept] of [
    [
      true,
      "Unpaired. This device's key is retired; open a new pairing link to pair again.",
      false,
    ],
    [false, "This device is not paired with the desk.", true],
  ]) {
    const store = memoryStore();
    const keys = await holderKey(store);
    const api = { unpair: async () => ({ unpaired }) };
    assert.equal(await unpairDevice(api, keys, store), note);
    assert.equal((await store.load()) === keys, kept);
  }
});

test("unpair posts the device key and its signature", async () => {
  const sent = [];
  const fetchFn = async (url, init) => {
    sent.push([url, JSON.parse(init.body)]);
    return { ok: true, json: async () => ({ unpaired: true }) };
  };
  await httpApi("http://desk", fetchFn).unpair("KEY", "SIG");
  assert.deepEqual(sent, [
    ["http://desk/api/holder/unpair", { public_key: "KEY", signature: "SIG" }],
  ]);
});

test("registerHolder posts the key with the pairing token", async () => {
  const sent = [];
  const fetchFn = async (url, init) => {
    sent.push([url, JSON.parse(init.body)]);
    return { ok: true, json: async () => ({ registered: true }) };
  };
  await httpApi("http://desk", fetchFn).registerHolder("KEY", "tok");
  assert.deepEqual(sent, [
    ["http://desk/api/holder", { public_key: "KEY", pairing: "tok" }],
  ]);
});

test("pairing refusal surfaces the desk error", async () => {
  const fetchFn = async () => ({ ok: false, status: 400 });
  const api = httpApi("http://desk", fetchFn);
  await assert.rejects(pair(api, "KEY", "#pair=spent"), /desk error 400/);
});

test(
  "live desk: pair holder, review, approve",
  { skip: !process.env.MANDATE_URL },
  async () => {
    const api = httpApi(process.env.MANDATE_URL);
    const keys = await holderKey(memoryStore());
    const raw = await crypto.subtle.exportKey("raw", keys.publicKey);
    const b64 = Buffer.from(raw).toString("base64");
    await assert.rejects(api.registerHolder(b64, "wrong"), /desk error 400/);
    const token = process.env.MANDATE_PAIR;
    assert.deepEqual(await api.registerHolder(b64, token), { registered: true });
    await assert.rejects(api.registerHolder(b64, token), /desk error 400/);
    const approver = new Approver(api, keys, () => {});
    assert.match(await approver.review("q:000001"), /acme-991/);
    assert.equal((await approver.approve()).status, "approved");
    assert.deepEqual(await api.pending(), []);
  },
);

test("voiceReason hides voice when the desk has it off", () => {
  assert.equal(voiceReason(null, true), null);
  assert.equal(voiceReason(null, false), "Voice is off on this desk");
  assert.equal(voiceReason("Voice is not supported in this browser", true),
    "Voice is not supported in this browser");
});

test("httpApi reads whether the desk has voice on", async () => {
  const body = { holders: 1, voice: true };
  const api = httpApi("http://desk", async () => ({ ok: true, json: async () => body }));
  assert.equal(await api.voiceOn(), true);
  const bad = httpApi("http://desk", async () => ({ ok: false, status: 500 }));
  assert.equal(await bad.voiceOn(), false);
  const odd = httpApi("http://desk", async () => ({ ok: true, json: async () => ({}) }));
  assert.equal(await odd.voiceOn(), false);
});

function voiceRig({ support = null } = {}) {
  const heard = { textContent: "" };
  const speak = { textContent: "Speak to confirm", disabled: true, hidden: false };
  const approver = { shownId: "q:000001" };
  const calls = { opened: 0, released: 0, sent: [] };
  let finish;
  const pendingMic = { resolve: null };
  const mic = {
    start() {},
    stop() {
      finish();
    },
    stopped: new Promise((resolve) => {
      finish = resolve;
    }),
    wav: async () => new Uint8Array([1, 2]),
    release() {
      calls.released += 1;
    },
  };
  const api = {
    transcribe: async (quote, wav, sig) => {
      calls.sent.push(quote);
      if (calls.hold) await calls.hold;
      if (calls.fail) throw new Error("Voice refused: model error");
      return "pay acme";
    },
  };
  const ui = new VoiceUi({
    heard,
    speak,
    approver,
    keys: {},
    api,
    support,
    sign: async () => "sig",
    openMic: async () => {
      calls.opened += 1;
      if (calls.gate) await calls.gate;
      if (calls.deny) throw new Error("denied");
      return mic;
    },
    schedule: () => 1,
    cancel: () => {},
  });
  return { heard, speak, approver, calls, ui, mic, pendingMic };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

test("voice off keeps the control hidden and never opens the microphone", async () => {
  const rig = voiceRig({ support: "Voice is off on this desk" });
  assert.equal(rig.speak.hidden, true);
  assert.equal(rig.heard.textContent, "Voice is off on this desk");
  rig.ui.quoteShown();
  await rig.ui.click();
  assert.equal(rig.calls.opened, 0);
  assert.equal(rig.speak.disabled, true);
});

test("a full take shows the words for the quote that is still shown", async () => {
  const rig = voiceRig();
  rig.ui.quoteShown();
  const run = rig.ui.click();
  await tick();
  assert.equal(rig.heard.textContent, "Listening. Tap Stop when done.");
  rig.ui.click();
  await run;
  assert.equal(rig.heard.textContent, 'You said: "pay acme"');
  assert.equal(rig.calls.released, 1);
});

test("switching quote while the permission prompt is open never listens", async () => {
  const rig = voiceRig();
  let open;
  rig.calls.gate = new Promise((resolve) => {
    open = resolve;
  });
  rig.ui.quoteShown();
  const run = rig.ui.click();
  rig.approver.shownId = "q:000002";
  rig.ui.quoteShown();
  open();
  await run;
  assert.equal(rig.heard.textContent, "");
  assert.equal(rig.calls.released, 1);
  assert.deepEqual(rig.calls.sent, []);
});

test("switching quote while listening clears the line and drops the clip", async () => {
  const rig = voiceRig();
  rig.ui.quoteShown();
  const run = rig.ui.click();
  await tick();
  rig.approver.shownId = "q:000002";
  rig.ui.quoteShown();
  assert.equal(rig.heard.textContent, "");
  await run;
  assert.equal(rig.heard.textContent, "");
  assert.deepEqual(rig.calls.sent, []);
});

test("an error for an earlier quote is not written beside another", async () => {
  const rig = voiceRig();
  rig.calls.fail = true;
  let release;
  rig.calls.hold = new Promise((resolve) => {
    release = resolve;
  });
  rig.ui.quoteShown();
  const run = rig.ui.click();
  await tick();
  rig.ui.click();
  await tick();
  assert.equal(rig.heard.textContent, "Transcribing.");
  rig.approver.shownId = "q:000002";
  rig.ui.quoteShown();
  assert.equal(rig.heard.textContent, "");
  release();
  await run;
  assert.equal(rig.heard.textContent, "");
});

test("a refused microphone is reported only for the shown quote", async () => {
  const rig = voiceRig();
  rig.calls.deny = true;
  rig.ui.quoteShown();
  await rig.ui.click();
  assert.equal(rig.heard.textContent, "Microphone refused: denied");
  assert.equal(rig.speak.disabled, false);
});

test("closing the shown quote clears the voice line", async () => {
  const rig = voiceRig();
  rig.ui.quoteShown();
  const run = rig.ui.click();
  await tick();
  rig.approver.shownId = null;
  rig.ui.cleared();
  await run;
  assert.equal(rig.heard.textContent, "");
  assert.equal(rig.speak.disabled, true);
});
