import { gameText } from "../ledger/narrate";
import { attackLabel, cueFor } from "../scene/cues";
import { parseLine } from "../wire/parse";

export interface HttpReply {
  readonly status: number;
  readonly text: string;
}
export type Http = (method: "GET" | "POST", path: string, body?: unknown) => Promise<HttpReply>;

/** Same-origin fetch; a body goes as JSON. */
export const fetchHttp: Http = async (method, path, body) => {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { "content-type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  return { status: res.status, text: await res.text() };
};

export interface AttackerState {
  readonly available: boolean;
  readonly provider: string | null;
  readonly model: string | null;
  readonly reason: string | null;
}
export interface AttackMenu {
  readonly templates: readonly { readonly kind: string; readonly narrative: string }[];
  readonly attacker: AttackerState;
}

export class MenuError extends Error {}

const malformed = () => new MenuError("attacks: malformed menu");
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const hasKeys = (o: Record<string, unknown>, keys: string[]) => Object.keys(o).length === keys.length && keys.every((k) => k in o);
const stringOrNull = (v: unknown): v is string | null => v === null || typeof v === "string";

/** Reads the attack menu exactly as the server shapes it. */
export function parseAttackMenu(text: string): AttackMenu {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw malformed();
  }
  if (!isRecord(raw) || !hasKeys(raw, ["templates", "attacker"])) throw malformed();
  const { templates, attacker } = raw;
  if (!Array.isArray(templates) || templates.length === 0) throw malformed();
  const kinds = templates.map((t: unknown) => {
    if (!isRecord(t) || !hasKeys(t, ["kind", "narrative"]) || typeof t.kind !== "string" || typeof t.narrative !== "string") throw malformed();
    return { kind: t.kind, narrative: t.narrative };
  });
  if (!isRecord(attacker) || !hasKeys(attacker, ["available", "provider", "model", "reason"])) throw malformed();
  const { available, provider, model, reason } = attacker;
  if (typeof available !== "boolean" || !stringOrNull(provider) || !stringOrNull(model) || !stringOrNull(reason)) throw malformed();
  return { templates: kinds, attacker: { available, provider, model, reason } };
}

const NAMES: Record<string, string> = {
  payee_swap: "Swap the payee",
  amount_inflate: "Inflate the amount",
  replay: "Replay the certificate",
  post_cert_mutation: "Change it after approval",
  scope_escalation: "Escalate the scope",
  mcp_exfil: "Poison an MCP tool",
  forged_approval: "Forge the holder's approval",
};
const STEPS: readonly (readonly [string, string])[] = [
  ["release", "Ship api-v2 to prod-eu"],
  ["poisoned_tool", "Poison the deploy tool"],
  ["stale_migration", "Re-run migration-0017"],
];

const nameOf = (kind: string) => NAMES[kind] ?? attackLabel(kind);
const refused = (status: number) => `Refused by the server (HTTP ${status})`;
const UNREACHABLE = "Server unreachable";

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, className?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className !== undefined) node.className = className;
  return node;
}

function labelled(name: string, badge: string, className: string): HTMLButtonElement {
  const button = el("button", undefined, className);
  button.type = "button";
  button.append(el("span", name, "name"), " ", el("span", badge, "badge"));
  return button;
}

/** The result copy for a published line, or the reason none came. */
function lineCopy(reply: HttpReply): string {
  if (reply.status !== 200) return refused(reply.status);
  try {
    const line = parseLine(reply.text);
    return `#${line.seq} ${cueFor(line).alert ?? gameText(line)}`;
  } catch {
    return "Unreadable reply from the server";
  }
}

/** Runs one press: busy while in flight, one request, the result written as text. */
async function press(button: HTMLButtonElement, out: HTMLElement, http: Http, path: string, body: unknown): Promise<void> {
  if (button.disabled) return;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    out.textContent = lineCopy(await http("POST", path, body));
  } catch {
    out.textContent = UNREACHABLE;
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

function detailOf(text: string, key: string): string | null {
  try {
    const raw: unknown = JSON.parse(text);
    const value = isRecord(raw) ? raw[key] : undefined;
    return typeof value === "string" ? value : null;
  } catch {
    return null;
  }
}

function modelCopy(reply: HttpReply): string {
  switch (reply.status) {
    case 200:
      return lineCopy(reply);
    case 502:
      return `No plan from the model: ${detailOf(reply.text, "detail") ?? "no detail"}`;
    case 409:
      return "Busy: one model attack at a time";
    case 503:
      return detailOf(reply.text, "reason") ?? refused(503);
    default:
      return refused(reply.status);
  }
}

function buildScenario(http: Http): HTMLElement {
  const section = el("section", undefined, "scenario");
  section.append(Object.assign(el("h3", "Nimbus deploy scenario"), { id: "scenario-title" }));
  section.setAttribute("aria-labelledby", "scenario-title");
  const list = el("ul", undefined, "steps");
  for (const [step, name] of STEPS) {
    const button = labelled(name, "SCENARIO", "scenario");
    button.dataset.step = step;
    const out = el("p", undefined, "result");
    out.dataset.step = step;
    out.setAttribute("role", "status");
    button.addEventListener("click", () => void press(button, out, http, "/api/deploy", { step }));
    const item = el("li");
    item.append(button, out);
    list.append(item);
  }
  section.append(list);
  return section;
}

function buildModel(menu: AttackMenu, http: Http): HTMLElement {
  const { attacker } = menu;
  const fallback = attacker.provider === "meta-fallback";
  const section = el("section", undefined, "model");
  section.setAttribute("aria-labelledby", "model-title");
  const select = el("select");
  select.id = "model-kind";
  for (const t of menu.templates) {
    const option = el("option", nameOf(t.kind));
    option.value = t.kind;
    select.append(option);
  }
  const label = el("label", "Attack kind");
  label.htmlFor = "model-kind";
  const ask = el("button", fallback ? "Ask the Meta fallback attacker" : "Ask the open-weights attacker");
  ask.type = "button";
  ask.id = "ask-model";
  const status = el("p");
  status.id = "model-status";
  const result = el("p", undefined, "result");
  result.id = "model-result";
  result.setAttribute("role", "status");
  ask.disabled = !attacker.available;
  if (!attacker.available) {
    status.textContent = attacker.reason ?? "";
  } else if (fallback) {
    status.textContent = `${attacker.model} via the Meta API (not open weights)`;
  } else {
    status.textContent = attacker.provider === "baseten" ? `${attacker.model} on Baseten` : `${attacker.model} via ${attacker.provider}`;
  }
  ask.addEventListener("click", async () => {
    if (ask.disabled) return;
    ask.disabled = true;
    ask.setAttribute("aria-busy", "true");
    result.textContent = `Asking ${attacker.model}…`;
    try {
      result.textContent = modelCopy(await http("POST", "/api/attack/model", { kind: select.value }));
    } catch {
      result.textContent = UNREACHABLE;
    } finally {
      ask.disabled = false;
      ask.removeAttribute("aria-busy");
    }
  });
  const title = Object.assign(el("h3", "Open-weights attacker"), { id: "model-title" });
  section.append(title, label, select, ask, status, result);
  return section;
}

function buildTemplates(list: HTMLElement, menu: AttackMenu, http: Http): void {
  for (const t of menu.templates) {
    const button = labelled(nameOf(t.kind), "TEMPLATE", "attack");
    button.dataset.kind = t.kind;
    button.setAttribute("aria-describedby", `what-${t.kind}`);
    const what = el("p", t.narrative, "what");
    what.id = `what-${t.kind}`;
    const out = el("p", undefined, "result");
    out.dataset.kind = t.kind;
    out.setAttribute("role", "status");
    button.addEventListener("click", () => void press(button, out, http, "/api/attack", { kind: t.kind }));
    const item = el("li");
    item.append(button, what, out);
    list.append(item);
  }
}

/** Mounts the attack panel into `root`; `ready` settles once the menu has loaded or failed. */
export function mountAttackPanel(root: HTMLElement, toggle: HTMLButtonElement, http: Http = fetchHttp): { ready: Promise<void> } {
  const setOpen = (open: boolean) => {
    root.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
  };
  toggle.addEventListener("click", () => setOpen(root.hidden !== false));
  root.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    setOpen(false);
    toggle.focus();
  });

  const title = Object.assign(el("h2", "Attack the gate"), { id: "attacks-title" });
  root.setAttribute("aria-labelledby", "attacks-title");
  const templates = el("ul", undefined, "templates");
  root.replaceChildren(title, el("p", "Pinned templates: the same press runs the same attack.", "note"), templates, buildScenario(http));

  const ready = (async () => {
    try {
      const reply = await http("GET", "/api/attack");
      if (reply.status !== 200) {
        root.append(el("p", `Attacks unavailable (HTTP ${reply.status})`, "menu-error"));
        return;
      }
      const menu = parseAttackMenu(reply.text);
      buildTemplates(templates, menu, http);
      root.append(buildModel(menu, http));
    } catch {
      root.append(el("p", "Attacks unavailable", "menu-error"));
    }
  })();
  return { ready };
}
