import assert from "node:assert/strict";
import { test } from "node:test";

import {
  Approver,
  consentBytes,
  describe,
  holderKey,
  httpApi,
  pair,
  registerTools,
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
  };
}

function fakeApi(pending) {
  const approvals = [];
  return {
    approvals,
    pending: async () => pending,
    approve: async (quoteId, signature) => {
      approvals.push({ quoteId, signature });
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
  const sig = Buffer.from(api.approvals[0].signature, "base64");
  const verify = (fields) =>
    crypto.subtle.verify(ED, keys.publicKey, sig, consentBytes(fields));
  assert.equal(await verify(evil), true);
  assert.equal(await verify(FIELDS), false);
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
  assert.match(await pair(api, "KEY", "#pair=tok-2"), /already paired/);
  assert.deepEqual(calls, [
    ["KEY", "tok-1"],
    ["KEY", "tok-2"],
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
