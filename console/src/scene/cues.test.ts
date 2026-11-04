import { expect, test } from "vitest";
import { HOSTILE } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { attack, bill, confirmed, desk, gateEvent, hook, NARRATIVE, SPARK_META, SUMMARY } from "./__fixtures__/cases";
import { cueFor } from "./cues";

test.each([
  ["mcp_exfil", "mcp", "thief", "denied · poisoned MCP tool · at the MCP proxy"],
  ["replay", "bank", "ghost", "denied · replayed certificate · at the bank verifier"],
  ["scope_escalation", "delegation", "brute", "denied · scope escalation · at the broker"],
  ["post_cert_mutation", "gate->bank", "switcher", "denied · changed after approval · at the bank verifier"],
])("blocked %s without a gate event sends a %s to the booth and names the layer", (kind, layer, actor, alert) => {
  expect(cueFor(attack(kind, layer))).toEqual({
    seq: 4, actor, route: "door", seal: "deny", outcome: "deny", tag: "template attack", bubble: NARRATIVE, alert, bank: false,
  });
});

test.each([
  ["payee_swap", 61.0, "denied · payee swapped · 61µs"],
  ["amount_inflate", 1234.5, "denied · amount inflated · 1.2ms"],
])("blocked %s decided by the gate shows the gate latency", (kind, us, alert) => {
  const c = cueFor(attack(kind, "model->gate", { gate: gateEvent("NOT_MET", "recipient differs from intent", us) }));
  expect([c.actor, c.seal, c.alert]).toEqual(["forger", "deny", alert]);
});

test("the golden model-planned exfiltration is the open-weights attacker as a thief", () => {
  const c = cueFor(parseLine(HOSTILE));
  expect([c.seq, c.actor, c.tag, c.alert]).toEqual([7, "thief", "open-weights attacker", "denied · poisoned MCP tool · at the MCP proxy"]);
});

test("an unknown attack kind still dies at the booth under its wire name", () => {
  expect(cueFor(attack("tool_swap", "mcp")).alert).toBe("denied · tool swap · at the MCP proxy");
});

test("an attack that was not blocked is a breach, never a verified seal", () => {
  const c = cueFor(attack("payee_swap", "model->gate", { blocked: false }));
  expect([c.outcome, c.seal, c.route, c.alert]).toEqual(["breach", null, "door", "NOT BLOCKED · payee swapped · 200.00 moved"]);
});

test("a quoted payment walks from the desks and holds the seal open", () => {
  expect(cueFor(desk("quote", "quoted", { meta: SPARK_META }))).toEqual({
    seq: 3, actor: "spark", route: "desk", seal: "wait", outcome: "hold", tag: "Muse Spark",
    bubble: `${SUMMARY} · waiting for the holder`, alert: null, bank: false,
  });
});

test("the holder's approval is shown at the booth without a walker", () => {
  const c = cueFor(desk("approve", "approved"));
  expect([c.actor, c.route, c.seal, c.outcome, c.tag, c.bubble]).toEqual(["holder", "none", "wait", "hold", "holder", `Holder approved: ${SUMMARY}`]);
});

test("the golden confirmed payment verifies the seal, pays the bank and quotes the gate latency", () => {
  const c = cueFor(confirmed());
  expect([c.actor, c.tag, c.route, c.seal, c.outcome, c.bank, c.bubble]).toEqual([
    "agent", "agent", "desk", "verify", "pass", true, `${SUMMARY} · verified · 61µs`,
  ]);
});

test.each([
  ["confirm", "denied", "consent: already used", "denied · consent: already used · 61µs", "desk"],
  ["approve", "expired", null, "denied · expired · 61µs", "none"],
])("a desk %s that ends %s denies at the booth", (step, status, reason, alert, route) => {
  const c = cueFor(desk(step, status, { event: gateEvent("NOT_MET", reason ?? status) }, { reason }));
  expect([c.seal, c.outcome, c.alert, c.route]).toEqual(["deny", "deny", alert, route]);
});

test("Muse Code's desk calls are walked by the Muse Code courier", () => {
  const c = cueFor(desk("quote", "quoted", { meta: { ...SPARK_META, provider: "muse-code", model: "muse-code-1.4" } }));
  expect([c.actor, c.tag]).toEqual(["code", "Muse Code"]);
});

test("an unknown desk status is noted in place and never moves the seal", () => {
  const c = cueFor(desk("confirm", "pending"));
  expect([c.route, c.seal, c.outcome, c.bubble]).toEqual(["none", null, "note", "confirm: pending"]);
});

test("Muse Code tool calls animate at the desks; denials still close the seal", () => {
  const allowed = cueFor(hook("MET", "ok"));
  expect([allowed.seal, allowed.bubble]).toEqual([null, "edit_file src/app.py · allowed"]);
  const denied = cueFor(hook("NOT_MET", "scope: path escapes worktree"));
  expect([denied.seal, denied.route, denied.alert]).toEqual(["deny", "none", "denied · edit_file · scope: path escapes worktree"]);
});

test("a bill Spark pays crosses the booth; a refused one dies there; a read one is narrated", () => {
  const paid = cueFor(bill(gateEvent("MET", "rule pay-intent satisfied")));
  expect([paid.actor, paid.seal, paid.bank, paid.bubble]).toEqual(["spark", "verify", true, `Bill paid: ${SUMMARY} · 61µs`]);
  const refused = cueFor(bill(gateEvent("NOT_MET", "recipient differs from intent")));
  expect([refused.seal, refused.alert]).toEqual(["deny", "denied · recipient differs from intent · 61µs"]);
  expect(cueFor(bill(null)).bubble).toBe(`Read bill: ${SUMMARY}`);
  expect(cueFor(bill(null, "timeout")).bubble).toBe("Bill report failed: timeout");
});

test("bubbles are cut to 120 characters", () => {
  const line = attack("mcp_exfil", "mcp");
  if (line.source !== "attack") throw new Error("fixture");
  const c = cueFor({ ...line, subject: { ...line.subject, narrative: "x".repeat(160) } });
  expect(c.bubble).toBe(`${"x".repeat(119)}…`);
});

test("a forged holder approval is a forger the gate refuses at the consent", () => {
  const c = cueFor(attack("forged_approval", "holder->gate", { gate: gateEvent("NOT_MET", "consent: bad signature", 61.0) }));
  expect([c.actor, c.seal, c.outcome, c.alert]).toEqual(["forger", "deny", "deny", "denied · forged approval · 61µs"]);
});

test("a forged approval without a gate event names the gate as its layer", () => {
  expect(cueFor(attack("forged_approval", "holder->gate")).alert).toBe("denied · forged approval · at the gate");
});
