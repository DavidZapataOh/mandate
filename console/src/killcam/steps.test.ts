import { expect, test } from "vitest";
import { ATTACK, CONFIRM, DEPLOY, patch } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { APPROVAL_DENIED, CLAIMS, CONSENT_DENIED, DENIALS, denial, FORGED_CONSENT, HOOK_DENIED, NIMBUS_POISONED, NIMBUS_STALE } from "./__fixtures__/denials";
import { killSteps, killedAt } from "./steps";

const SWAP_HASH = "89f0357807b9d6e90a1c66d00e2a058ad97a5370349978a0ddceb67c50653f9a";
const LEGIT_HASH = "20fa07c63133f7b15e26cebafeecff3f7bbdd4c61ee311b81ec8aa42e1dc8868";
const UNREACHED = (id: string, title: string) => ({ id, title, status: "unreached", detail: "Not reached", evidence: null });
const AFTER_GATE_FAIL = [
  UNREACHED("consent", "Holder consent"),
  UNREACHED("certificate", "Certificate"),
  UNREACHED("bank", "Bank verifier"),
];
const GATE_UNREACHED = [
  UNREACHED("canonicalize", "Canonicalize"),
  UNREACHED("hash", "Hash"),
  UNREACHED("policy", "Policy rule"),
  ...AFTER_GATE_FAIL,
];
const canon = (to: string, amount: string) => ({
  id: "canonicalize",
  title: "Canonicalize",
  status: "passed",
  detail: "bank.pay transfer · 4 targets",
  evidence: `{"category":"payments","evidence_refs":[],"executable":"bank.pay","freshness":{"nonce":"atk00000000000000000000000000003","timestamp":1800001000},"operation":"transfer","reversible":false,"runtime":"muse","targets":["amount:USD:${amount}","from:checking-881","ref:A-991","to:${to}"],"version":"cava/1"}`,
});
const hash = (h: string) => ({ id: "hash", title: "Hash", status: "passed", detail: h, evidence: null });
const certifiedSteps = (reason: string) => [
  canon("acme-991", "20000"),
  hash(LEGIT_HASH),
  { id: "policy", title: "Policy rule", status: "passed", detail: "rule pay-intent satisfied", evidence: null },
  { id: "consent", title: "Holder consent", status: "skipped", detail: "No consent presented", evidence: null },
  {
    id: "certificate",
    title: "Certificate",
    status: "passed",
    detail: "MET over 20fa07c63133 · revocation index 0",
    evidence: JSON.stringify(CLAIMS),
  },
  { id: "bank", title: "Bank verifier", status: "failed", detail: reason, evidence: null },
];

test.each([
  [
    "payee_swap",
    [
      canon("evil-666", "20000"),
      hash(SWAP_HASH),
      { id: "policy", title: "Policy rule", status: "failed", detail: "recipient differs from intent", evidence: "rule pay-intent · NOT_MET" },
      ...AFTER_GATE_FAIL,
    ],
  ],
  [
    "amount_inflate",
    [
      canon("acme-991", "2000000"),
      hash("b7df0f538186d50487f61c22718995525d0e69e18dae56694359292f9b43a471"),
      { id: "policy", title: "Policy rule", status: "failed", detail: "amount differs from intent", evidence: "rule pay-intent · NOT_MET" },
      ...AFTER_GATE_FAIL,
    ],
  ],
  ["replay", certifiedSteps("replay: jti consumed")],
  ["post_cert_mutation", certifiedSteps("mismatch: action hash differs")],
  [
    "scope_escalation",
    [{ id: "broker", title: "Broker", status: "failed", detail: "scope: target outside delegation", evidence: null }, ...GATE_UNREACHED],
  ],
  [
    "mcp_exfil",
    [{ id: "mcp", title: "MCP proxy", status: "failed", detail: "denied: server undeclared", evidence: null }, ...GATE_UNREACHED],
  ],
])("killcam steps match payload: %s", (kind, want) => {
  expect(killSteps(denial(kind))).toEqual(want);
});

test.each([
  ["payee_swap", "Killed at Policy rule: recipient differs from intent"],
  ["replay", "Killed at Bank verifier: replay: jti consumed"],
  ["mcp_exfil", "Killed at MCP proxy: denied: server undeclared"],
])("the tape names where %s died", (kind, want) => {
  expect(killedAt(killSteps(denial(kind))!)).toBe(want);
});

test("a consent refusal passes the policy and fails at the holder's consent", () => {
  const steps = killSteps(parseLine(CONSENT_DENIED))!;
  expect(steps.map((s) => [s.id, s.status, s.detail])).toEqual([
    ["canonicalize", "passed", "bank.pay transfer · 4 targets"],
    ["hash", "passed", "52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b"],
    ["policy", "passed", "rule pay-with-consent satisfied"],
    ["consent", "failed", "consent: expired"],
    ["certificate", "unreached", "Not reached"],
    ["bank", "unreached", "Not reached"],
  ]);
});

test("a refused approval dies at the desk before anything reaches the gate", () => {
  expect(killSteps(parseLine(APPROVAL_DENIED))!.slice(0, 2)).toEqual([
    { id: "desk", title: "Desk", status: "failed", detail: "consent: bad signature", evidence: null },
    UNREACHED("canonicalize", "Canonicalize"),
  ]);
});

test("a hook denial shows the hash the gate computed without inventing its canonical object", () => {
  expect(killSteps(parseLine(HOOK_DENIED))!.slice(0, 3)).toEqual([
    { id: "canonicalize", title: "Canonicalize", status: "passed", detail: "Canonical object not recorded in this line", evidence: null },
    hash(SWAP_HASH),
    { id: "policy", title: "Policy rule", status: "failed", detail: "scope: target outside delegation", evidence: "policy delegation · NOT_MET" },
  ]);
});

test.each([
  ["a paid line", CONFIRM],
  ["an attack that was not blocked", patch(ATTACK, {}, { blocked: false, reason: "ok: executed" })],
  ["a gate denial that carries certificate claims", patch(ATTACK, { forensic: { ...JSON.parse(DENIALS.replay!).forensic, action_hash: SWAP_HASH, cava: JSON.parse(ATTACK).forensic.cava } })],
  ["a hash that differs between event and forensic", patch(ATTACK, { event: { ...JSON.parse(ATTACK).event, action: LEGIT_HASH } })],
  ["a certified denial without claims", patch(DENIALS.replay!, { forensic: { ...JSON.parse(DENIALS.replay!).forensic, cert_claims: null } })],
  ["claims over another action", patch(DENIALS.replay!, { forensic: { ...JSON.parse(DENIALS.replay!).forensic, action_hash: SWAP_HASH } })],
  ["an unknown layer that never reached the gate", patch(DENIALS.mcp_exfil!, {}, { layer: "firewall" })],
])("no kill-cam for %s", (_name, text) => {
  expect(killSteps(parseLine(text))).toBeNull();
});

const PAST_GATE = (claims: Record<string, unknown>) => {
  const base = JSON.parse(DENIALS.replay!);
  return patch(DENIALS.replay!, {
    event: { ...JSON.parse(ATTACK).event, verdict: "MET", action: LEGIT_HASH, reason: "ok", cert: "cert-1" },
    forensic: { ...base.forensic, cert_claims: claims },
  });
};

test("a refusal past the gate shows the certificate only when its claims are over the gate's action", () => {
  expect(killSteps(parseLine(PAST_GATE(CLAIMS)))).not.toBeNull();
  expect(killSteps(parseLine(PAST_GATE({ ...CLAIMS, action_hash: SWAP_HASH })))).toBeNull();
});

test("the Nimbus poisoned tool dies at the MCP proxy after it hashed the call", () => {
  expect(killSteps(parseLine(NIMBUS_POISONED))).toEqual([
    {
      id: "canonicalize",
      title: "Canonicalize",
      status: "passed",
      detail: "mcp:nimbus-mcp secrets.export · 1 targets",
      evidence: '{"category":"mcp","evidence_refs":[],"executable":"mcp:nimbus-mcp","freshness":{"nonce":"dep00000000000000000000000000010","timestamp":1800001000},"operation":"secrets.export","reversible":true,"runtime":"mcp","targets":["scope=net:collector.evil.com"],"version":"cava/1"}',
    },
    hash("511282b863031996cfca1ab4878bda998ea9cbe253b8731e89e8cd659414243e"),
    { id: "mcp", title: "MCP proxy", status: "failed", detail: "denied: tool undeclared", evidence: "manifest:nimbus-mcp · NOT_MET" },
    UNREACHED("policy", "Policy rule"),
    UNREACHED("consent", "Holder consent"),
    UNREACHED("certificate", "Certificate"),
    UNREACHED("target", "Deploy target"),
  ]);
});

test("a forged approval passes the policy and dies at the holder's consent, showing what was signed", () => {
  expect(killSteps(denial("forged_approval"))).toEqual([
    { ...canon("evil-666", "20000"), evidence: canon("evil-666", "20000").evidence.replace('"runtime":"muse"', '"runtime":"mcp"') },
    hash("083d5271bec37350a77e45db957a3e65a0fe00d7413fa4f2dc2999502ee8fd8d"),
    { id: "policy", title: "Policy rule", status: "passed", detail: "rule pay-with-consent satisfied", evidence: null },
    { id: "consent", title: "Holder consent", status: "failed", detail: "consent: bad signature", evidence: JSON.stringify(FORGED_CONSENT) },
    ...AFTER_GATE_FAIL.slice(1),
  ]);
  expect(killedAt(killSteps(denial("forged_approval"))!)).toBe("Killed at Holder consent: consent: bad signature");
});

test("the Nimbus stale migration matches no rule and never reaches the deploy target", () => {
  const steps = killSteps(parseLine(NIMBUS_STALE))!;
  expect(steps.map((s) => [s.id, s.status, s.detail, s.evidence])).toEqual([
    ["canonicalize", "passed", "nimbus migrate · 2 targets", expect.any(String)],
    ["hash", "passed", "f960d447b69f99f31b0f80708cede65fb4a9dfe2c78f1f45281acf1235095762", null],
    ["policy", "failed", "no rule matches", "policy nimbus · NOT_MET"],
    ["consent", "unreached", "Not reached", null],
    ["certificate", "unreached", "Not reached", null],
    ["target", "unreached", "Not reached", null],
  ]);
  expect(killedAt(steps)).toBe("Killed at Policy rule: no rule matches");
});

test.each([
  ["the certified release", DEPLOY],
  ["a poisoned tool the proxy let through", patch(NIMBUS_POISONED, {}, { blocked: false, reason: "ok: declared" })],
])("no kill-cam for %s", (_name, text) => {
  expect(killSteps(parseLine(text))).toBeNull();
});
