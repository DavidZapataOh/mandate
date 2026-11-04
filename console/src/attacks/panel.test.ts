import { beforeEach, expect, test } from "vitest";
import { DENIALS, NIMBUS_POISONED, NIMBUS_STALE } from "../killcam/__fixtures__/denials";
import { ATTACK, DEPLOY, HOSTILE, patch } from "../wire/__fixtures__/lines";
import { BASETEN, FALLBACK, menu, OFF } from "./__fixtures__/menu";
import { type Http, mountAttackPanel, parseAttackMenu } from "./panel";

interface Call {
  method: string;
  path: string;
  body: unknown;
}

let root: HTMLElement;
let toggle: HTMLButtonElement;
let calls: Call[];
let answers: Map<string, Array<{ status: number; text: string } | Promise<{ status: number; text: string }>>>;

const http: Http = (method, path, body) => {
  calls.push({ method, path, body });
  const queue = answers.get(`${method} ${path}`) ?? [];
  const next = queue.shift();
  return next === undefined ? Promise.reject(new TypeError("Failed to fetch")) : Promise.resolve(next);
};
const answer = (key: string, status: number, text: string) => {
  answers.set(key, [...(answers.get(key) ?? []), { status, text }]);
};
const settle = () => new Promise((r) => setTimeout(r, 0));
const q = <T extends Element>(sel: string) => root.querySelector<T>(sel)!;
const attackButton = (kind: string) => q<HTMLButtonElement>(`button.attack[data-kind="${kind}"]`);
const result = (kind: string) => q(`.result[data-kind="${kind}"]`).textContent;

beforeEach(() => {
  document.body.innerHTML =
    '<button type="button" id="attacks-toggle" aria-expanded="false" aria-controls="attacks">ATTACK</button><aside id="attacks" hidden></aside>';
  root = document.getElementById("attacks")!;
  toggle = document.getElementById("attacks-toggle") as HTMLButtonElement;
  calls = [];
  answers = new Map();
});

test("the menu parser takes the server's exact shape and nothing else", () => {
  expect(parseAttackMenu(menu()).templates).toHaveLength(7);
  for (const bad of ["{", "[]", JSON.stringify({ templates: [], attacker: {} }), menu({ available: "yes", provider: null, model: null, reason: null })]) {
    expect(() => parseAttackMenu(bad)).toThrow("attacks: malformed menu");
  }
});

test("the toggle opens and closes the panel", async () => {
  answer("GET /api/attack", 200, menu());
  mountAttackPanel(root, toggle, http);
  toggle.click();
  expect([root.hidden, toggle.getAttribute("aria-expanded")]).toEqual([false, "true"]);
  root.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  expect([root.hidden, toggle.getAttribute("aria-expanded"), document.activeElement]).toEqual([true, "false", toggle]);
});

test("seven labelled template buttons, each with the server's narrative as its description", async () => {
  answer("GET /api/attack", 200, menu());
  await mountAttackPanel(root, toggle, http).ready;
  const buttons = [...root.querySelectorAll<HTMLButtonElement>("button.attack")];
  expect(buttons.map((b) => [b.dataset.kind, b.querySelector(".name")!.textContent, b.querySelector(".badge")!.textContent])).toEqual([
    ["payee_swap", "Swap the payee", "TEMPLATE"],
    ["amount_inflate", "Inflate the amount", "TEMPLATE"],
    ["replay", "Replay the certificate", "TEMPLATE"],
    ["post_cert_mutation", "Change it after approval", "TEMPLATE"],
    ["scope_escalation", "Escalate the scope", "TEMPLATE"],
    ["mcp_exfil", "Poison an MCP tool", "TEMPLATE"],
    ["forged_approval", "Forge the holder's approval", "TEMPLATE"],
  ]);
  const described = document.getElementById(buttons[2]!.getAttribute("aria-describedby")!)!;
  expect(described.textContent).toBe("MANDATE_FIXTURE Pay the 200.00 USD bill, then present its certificate a second time.");
});

test("a press posts its kind once and shows where the attack died", async () => {
  answer("GET /api/attack", 200, menu());
  await mountAttackPanel(root, toggle, http).ready;
  let release!: (v: { status: number; text: string }) => void;
  answers.set("POST /api/attack", [new Promise((r) => (release = r))]);
  attackButton("mcp_exfil").click();
  attackButton("mcp_exfil").click();
  expect(attackButton("mcp_exfil").disabled).toBe(true);
  expect(attackButton("mcp_exfil").getAttribute("aria-busy")).toBe("true");
  release({ status: 200, text: DENIALS.mcp_exfil! });
  await settle();
  expect(calls.filter((c) => c.method === "POST")).toEqual([{ method: "POST", path: "/api/attack", body: { kind: "mcp_exfil" } }]);
  expect(result("mcp_exfil")).toBe("#4 denied · poisoned MCP tool · at the MCP proxy");
  expect(attackButton("mcp_exfil").disabled).toBe(false);
});

test("a breach is reported as not blocked", async () => {
  answer("GET /api/attack", 200, menu());
  await mountAttackPanel(root, toggle, http).ready;
  answer("POST /api/attack", 200, patch(ATTACK, {}, { blocked: false, moved_cents: 20000, reason: "ok: executed" }));
  attackButton("payee_swap").click();
  await settle();
  expect(result("payee_swap")).toBe("#4 NOT BLOCKED · payee swapped · 200.00 moved");
});

test.each([
  [{ status: 400, text: '{"error": "bad request"}' }, "Refused by the server (HTTP 400)"],
  [null, "Server unreachable"],
])("a failed press says so: %o", async (reply, want) => {
  answer("GET /api/attack", 200, menu());
  await mountAttackPanel(root, toggle, http).ready;
  if (reply !== null) answer("POST /api/attack", reply.status, reply.text);
  attackButton("replay").click();
  await settle();
  expect(result("replay")).toBe(want);
});

test("without an attacker the model control is disabled and says why", async () => {
  answer("GET /api/attack", 200, menu());
  await mountAttackPanel(root, toggle, http).ready;
  expect(q<HTMLButtonElement>("#ask-model").disabled).toBe(true);
  expect(q("#ask-model").textContent).toBe("Ask the open-weights attacker");
  expect(q("#model-status").textContent).toBe(OFF);
  expect([...root.querySelectorAll("#model-kind option")].map((o) => (o as HTMLOptionElement).value)).toEqual([
    "payee_swap", "amount_inflate", "replay", "post_cert_mutation", "scope_escalation", "mcp_exfil", "forged_approval",
  ]);
});

test.each([
  [BASETEN, "Ask the open-weights attacker", "meta-models/muse-spark-open-1026 on Baseten"],
  [FALLBACK, "Ask the Meta fallback attacker", "muse-spark-1.3 via the Meta API (not open weights)"],
])("the model control names its provider honestly", async (attacker, label, note) => {
  answer("GET /api/attack", 200, menu(attacker));
  await mountAttackPanel(root, toggle, http).ready;
  expect([q<HTMLButtonElement>("#ask-model").disabled, q("#ask-model").textContent, q("#model-status").textContent]).toEqual([false, label, note]);
});

test("asking the model posts the chosen kind and shows its line as text", async () => {
  answer("GET /api/attack", 200, menu(BASETEN));
  await mountAttackPanel(root, toggle, http).ready;
  answer("POST /api/attack/model", 200, HOSTILE);
  q<HTMLSelectElement>("#model-kind").value = "mcp_exfil";
  q<HTMLButtonElement>("#ask-model").click();
  expect(q("#model-result").textContent).toBe("Asking meta-models/muse-spark-open-1026…");
  await settle();
  expect(calls.at(-1)).toEqual({ method: "POST", path: "/api/attack/model", body: { kind: "mcp_exfil" } });
  expect(q("#model-result").textContent).toBe("#7 denied · poisoned MCP tool · at the MCP proxy");
  expect(root.querySelector("img")).toBeNull();
});

test("the provider note stays visible after a model press", async () => {
  answer("GET /api/attack", 200, menu(FALLBACK));
  await mountAttackPanel(root, toggle, http).ready;
  answer("POST /api/attack/model", 200, HOSTILE);
  q<HTMLButtonElement>("#ask-model").click();
  await settle();
  expect(q("#model-status").textContent).toBe("muse-spark-1.3 via the Meta API (not open weights)");
  expect(q("#model-result").textContent).toBe("#7 denied · poisoned MCP tool · at the MCP proxy");
  expect(q("#model-result").getAttribute("role")).toBe("status");
});

test.each([
  [502, '{"error": "attacker gave no plan", "detail": "plan: not JSON | raw: <img src=x onerror=alert(1)>"}', "No plan from the model: plan: not JSON | raw: <img src=x onerror=alert(1)>"],
  [409, '{"error": "attacker busy"}', "Busy: one model attack at a time"],
  [503, '{"error": "attacker unavailable", "reason": "No attacker key: set BASETEN_API_KEY or a Meta key"}', "No attacker key: set BASETEN_API_KEY or a Meta key"],
])("a model refusal %d is shown as text", async (status, text, want) => {
  answer("GET /api/attack", 200, menu(BASETEN));
  await mountAttackPanel(root, toggle, http).ready;
  answer("POST /api/attack/model", status, text);
  q<HTMLButtonElement>("#ask-model").click();
  await settle();
  expect(q("#model-result").textContent).toBe(want);
  expect(root.querySelector("img")).toBeNull();
});

test("a menu the server cannot serve leaves the buttons out and says so", async () => {
  answer("GET /api/attack", 404, '{"error": "not found"}');
  await mountAttackPanel(root, toggle, http).ready;
  expect(root.querySelectorAll("button.attack")).toHaveLength(0);
  expect(q(".menu-error").textContent).toBe("Attacks unavailable (HTTP 404)");
});

const scenarioButton = (step: string) => q<HTMLButtonElement>(`button.scenario[data-step="${step}"]`);
const scenarioResult = (step: string) => q(`.result[data-step="${step}"]`).textContent;

test("the Nimbus scenario has its own three buttons labelled SCENARIO, even without the attack menu", async () => {
  answer("GET /api/attack", 404, '{"error": "not found"}');
  await mountAttackPanel(root, toggle, http).ready;
  expect(q("#scenario-title").textContent).toBe("Nimbus deploy scenario");
  expect([...root.querySelectorAll<HTMLButtonElement>("button.scenario")].map((b) => [b.dataset.step, b.querySelector(".name")!.textContent, b.querySelector(".badge")!.textContent])).toEqual([
    ["release", "Ship api-v2 to prod-eu", "SCENARIO"],
    ["poisoned_tool", "Poison the deploy tool", "SCENARIO"],
    ["stale_migration", "Re-run migration-0017", "SCENARIO"],
  ]);
});

test.each([
  ["release", DEPLOY, "#9 Released ✓ MANDATE_FIXTURE Deploy api-v2 to prod-eu in 18µs"],
  ["poisoned_tool", NIMBUS_POISONED, "#10 denied · poisoned MCP tool · 18µs"],
  ["stale_migration", NIMBUS_STALE, "#11 denied · stale migration · 18µs"],
])("a scenario press posts %s once and shows what the gate did", async (step, line, want) => {
  answer("GET /api/attack", 200, menu());
  await mountAttackPanel(root, toggle, http).ready;
  answer("POST /api/deploy", 200, line);
  scenarioButton(step).click();
  expect(scenarioButton(step).disabled).toBe(true);
  await settle();
  expect(calls.filter((c) => c.path === "/api/deploy")).toEqual([{ method: "POST", path: "/api/deploy", body: { step } }]);
  expect(scenarioResult(step)).toBe(want);
});

test("a scenario the server does not run says so", async () => {
  answer("GET /api/attack", 200, menu());
  await mountAttackPanel(root, toggle, http).ready;
  answer("POST /api/deploy", 404, '{"error": "not found"}');
  scenarioButton("release").click();
  await settle();
  expect(scenarioResult("release")).toBe("Refused by the server (HTTP 404)");
});
