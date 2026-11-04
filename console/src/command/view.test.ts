import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { LineStore } from "../store/store";
import type { ConsoleLine } from "../wire/types";
import { SERVER_BODY } from "./__fixtures__/provenance";
import { attackLine, BREACH, lines, WINDOW } from "./__fixtures__/window";
import { ATTACK_KINDS, DEFINITIONS } from "./posture";
import { parseProvenance, type ServerProvenance } from "./provenance";
import { type CommandDeps, mountCommand, provenanceSummary } from "./view";

const PAGE = new DOMParser().parseFromString(
  readFileSync("command.html", "utf8"),
  "text/html",
);
const AT = Date.UTC(2026, 10, 3, 17, 0, 0);

type Download = [name: string, mime: string, text: string];

function setup(opts: { server?: ServerProvenance | null; replay?: string | null; window?: readonly ConsoleLine[] } = {}) {
  document.body.innerHTML = PAGE.body.innerHTML;
  const store = new LineStore();
  for (const line of opts.window ?? lines(WINDOW)) store.add(line);
  const downloads: Download[] = [];
  const loads = { count: 0 };
  const deps: CommandDeps = {
    replay: opts.replay ?? null,
    fetchLine: async () => null,
    loadProvenance: async () => {
      loads.count += 1;
      return opts.server === undefined ? parseProvenance(SERVER_BODY) : opts.server;
    },
    now: () => AT,
    download: (name, mime, text) => downloads.push([name, mime, text]),
    schedule: (run) => run(),
  };
  const view = mountCommand(document, store, deps);
  return { store, downloads, loads, view };
}

const text = (sel: string) => document.querySelector(sel)?.textContent;
const click = (sel: string) => document.querySelector<HTMLButtonElement>(sel)!.click();

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("mountCommand", () => {
  it("shows each metric with its value and its exact definition", async () => {
    setup();
    await vi.waitFor(() => expect(text("#provenance")).toContain("(server)"));
    expect(text('[data-metric="decided"] .value')).toBe("7");
    expect(text('[data-metric="moved"] .value')).toBe("0.00");
    expect(text('[data-metric="consent"] .value')).toBe("1 of 2 · 50.0%");
    expect(text('[data-metric="latency"] .value')).toBe("p50 61µs · p95 90µs (5 samples)");
    for (const key of ["decided", "verified", "denied", "breaches", "moved", "consent", "latency", "attribution"] as const) {
      expect(text(`[data-metric="${key}"] .definition`)).toBe(DEFINITIONS[key]);
    }
  });

  it("names the window and the registry root it rests on", async () => {
    setup();
    await vi.waitFor(() =>
      expect(text("#provenance")).toBe(
        "Lines #1 to #9 (9 lines) · registry root 70566024e09c9a9e over 1 entry (server)",
      ),
    );
  });

  it("falls back to the newest line's registry proof when the server cannot say", async () => {
    setup({ server: null });
    await vi.waitFor(() => expect(text("#provenance")).toContain("(line #3)"));
  });

  it("a replay never asks the server and says it is a replay", async () => {
    const { loads } = setup({ replay: "demo-1" });
    await Promise.resolve();
    expect(loads.count).toBe(0);
    expect(text("#provenance")).toBe(
      "Replay demo-1 · Lines #1 to #9 (9 lines) · registry root 70566024e09c9a9e over 1 entry (line #3)",
    );
  });

  it("lists every attack kind, the untried ones as not attempted", () => {
    setup();
    const row = (kind: string) => [...document.querySelectorAll(`[data-kind="${kind}"] > *`)].slice(0, 6).map((c) => c.textContent);
    expect(row("payee_swap")).toEqual(["payee swapped", "1", "1", "0", "0.00", "gate"]);
    expect(row("scope_escalation")).toEqual(["scope escalation", "0", "0", "0", "0.00", "not attempted"]);
  });

  it("a metric drills into its real lines, newest first, each opening its record", () => {
    setup();
    click('[data-metric="denied"] button.drill');
    expect(document.querySelector<HTMLElement>("#drill")!.hidden).toBe(false);
    expect(text("#drill-title")).toBe("Denied before execution · 4 lines");
    const rows = [...document.querySelectorAll<HTMLButtonElement>("#drill li button")];
    expect(rows.map((b) => b.dataset["seq"])).toEqual(["8", "6", "5", "4"]);
    expect(rows[3]!.querySelector(".row")!.textContent).toBe("#4 attack NOT_MET 89f0357807b9 recipient differs from intent");
    rows[3]!.click();
    return vi.waitFor(() => {
      expect(document.querySelector<HTMLElement>("#forensic")!.hidden).toBe(false);
      expect(text("#forensic h2")).toBe("Line #4 · attack");
    });
  });

  it("a drill follows the live window", () => {
    const { store } = setup();
    click('[data-metric="verified"] button.drill');
    const seven = lines(WINDOW)[6]!;
    store.add({ ...seven, seq: 12 });
    expect(text("#drill-title")).toBe("Verified · 4 lines");
    expect(text('[data-metric="verified"] .value')).toBe("4");
  });

  it("text from the wire stays text", () => {
    const hostile = lines(WINDOW)[6]!;
    if (hostile.source !== "hook") throw new Error("fixture");
    setup({ window: [{ ...hostile, subject: { ...hostile.subject, agent: '<img src=x onerror="window.pwned=1">' } }] });
    click('[data-metric="verified"] button.drill');
    expect(text("#drill li .sentence")).toContain('<img src=x onerror="window.pwned=1">');
    expect(document.querySelector("#drill img")).toBeNull();
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  });

  it("exports Markdown and JSON from a fresh provenance read", async () => {
    const { downloads, loads, view } = setup();
    await view.exportReport("md");
    await view.exportReport("json");
    expect(loads.count).toBe(3);
    expect(downloads.map(([name, mime]) => [name, mime])).toEqual([
      ["mandate-posture-1-9.md", "text/markdown"],
      ["mandate-posture-1-9.json", "application/json"],
    ]);
    expect(downloads[0]![2].startsWith("# Mandate posture report\n")).toBe(true);
    expect(JSON.parse(downloads[1]![2]).provenance.registry.from).toBe("server");
  });

  it("an empty window still renders and exports", async () => {
    const { downloads, view } = setup({ window: [] });
    expect(text('[data-metric="latency"] .value')).toBe("no gate events in this window");
    await view.exportReport("md");
    expect(downloads[0]![0]).toBe("mandate-posture-empty.md");
  });

  it("a single line reads in the singular", async () => {
    setup({ window: lines(WINDOW).slice(8) });
    await vi.waitFor(() => expect(text("#provenance")).toMatch(/^Lines #9 to #9 \(1 line\) · lines before #9 are outside this window · registry root /));
    click('[data-metric="verified"] button.drill');
    expect(text("#drill-title")).toBe("Verified · 1 line");
    expect(text('[data-metric="verified"] button.drill')).toBe("Show the 1 line");
    expect(text('[data-metric="latency"] .value')).toBe("p50 90µs · p95 90µs (1 sample)");
  });

  it("an empty drill says so and a new line fills it", () => {
    const { store } = setup({ window: [] });
    click('[data-kind="replay"] button.drill');
    expect(text("#drill-title")).toBe("replayed certificate · 0 lines");
    expect(text("#drill li")).toBe("No lines in this window");
    store.add(lines(WINDOW)[5]!);
    expect([...document.querySelectorAll<HTMLElement>("#drill li button")].map((b) => b.dataset["seq"])).toEqual(["6"]);
  });

  it("a layer drills into the denials it made", () => {
    setup();
    click('[data-layer="MCP proxy"] button.drill');
    expect(text("#drill-title")).toBe("Denied at the MCP proxy · 1 line");
    expect(text('[data-layer="MCP proxy"] > td:nth-of-type(2)')).toBe("poisoned MCP tool");
  });

  it("maps each control with this window's evidence", () => {
    setup();
    expect(text("#disclaimer")).toBe("This report maps Mandate controls to framework provisions. It is not a certification, an audit opinion or a statement of compliance.");
    expect(document.querySelectorAll("#controls tbody tr")).toHaveLength(17);
    expect(text('[data-control="EU AI Act Article 73(1)"] .evidence')).toBe("0 attacks not blocked");
    const link = document.querySelector<HTMLAnchorElement>('[data-control="EU AI Act Article 73(1)"] a')!;
    expect([link.textContent, link.rel, link.href]).toEqual(["source", "noreferrer", "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"]);
  });

  it("zero-valued tiles are marked so only real alerts take the alert colour", () => {
    setup();
    expect(document.querySelector<HTMLElement>('[data-metric="moved"]')!.dataset["zero"]).toBe("true");
    expect(document.querySelector<HTMLElement>('[data-metric="denied"]')!.dataset["zero"]).toBe("false");
  });

  it("the drill is not a live region; opening one is announced once", () => {
    const { store } = setup();
    expect(document.querySelector("#drill")!.hasAttribute("aria-live")).toBe(false);
    const status = document.querySelector<HTMLElement>("#drill-status")!;
    expect([status.getAttribute("role"), status.textContent]).toEqual(["status", ""]);
    click('[data-metric="verified"] button.drill');
    expect(status.textContent).toBe("Opened Verified · 3 lines");
    store.add({ ...lines(WINDOW)[6]!, seq: 12 });
    expect(text("#drill-title")).toBe("Verified · 4 lines");
    expect(status.textContent).toBe("Opened Verified · 3 lines");
  });

  it("an attack attempted and not blocked reads not stopped, in words and the alert style", () => {
    setup({ window: lines([...WINDOW, BREACH]) });
    const stopped = document.querySelectorAll('[data-kind="amount_inflate"] > *')[5]!;
    expect(stopped.textContent).toBe("not stopped");
    expect(stopped.querySelector(".alert")!.textContent).toBe("not stopped");
    expect(document.querySelectorAll('[data-kind="payee_swap"] > *')[5]!.querySelector(".alert")).toBeNull();
  });

  it("an attack blocked once and let through once names both", () => {
    const blocked = lines([BREACH.replace('"seq":10', '"seq":11').replace('"blocked":false', '"blocked":true').replace('"moved_cents":2000000', '"moved_cents":0').replace('ok: executed', 'amount: exceeds intent')]);
    setup({ window: [...lines([BREACH]), ...blocked] });
    expect(document.querySelectorAll('[data-kind="amount_inflate"] > *')[5]!.textContent).toBe("gate, not stopped");
  });

  it("labels every register cell with its column, so a phone can stack the row", () => {
    setup();
    const row = document.querySelector('[data-control="NIST AI RMF 1.0 GOVERN 1.4"]')!;
    expect([...row.children].map((c) => (c as HTMLElement).dataset["label"])).toEqual([
      "Framework", "Provision", "Maps to (Mandate control)", "Evidence in this window", "Gap", "Source",
    ]);
  });

  it("names how many provisions the register maps", () => {
    setup();
    expect(text("#provisions")).toBe("17 provisions");
  });

  it("the register says whether it is scrolled to its end", () => {
    setup();
    expect(document.querySelector<HTMLElement>(".register")!.dataset["atEnd"]).toBe("true");
  });

  it("splits the gate time into its percentiles and its sample count", () => {
    setup();
    expect(text('[data-metric="latency"] .value .sub')).toBe("(5 samples)");
    expect(text('[data-metric="latency"] .value')).toBe("p50 61µs · p95 90µs (5 samples)");
  });

  it("keeps a share's count and its percentage each whole, so a line never ends on the dot", () => {
    setup();
    const parts = (key: string) => [...document.querySelectorAll(`[data-metric="${key}"] .value .part`)].map((e) => e.textContent);
    expect(parts("consent")).toEqual(["1 of 2", "· 50.0%"]);
    expect(parts("attribution")).toEqual(["4 of 7", "· 57.1%"]);
    expect(text('[data-metric="consent"] .value')).toBe("1 of 2 · 50.0%");
  });

  it("marks a value that says the window has none, so it reads as a sentence", () => {
    setup({ window: [] });
    expect(document.querySelector<HTMLElement>('[data-metric="consent"]')!.dataset["none"]).toBe("true");
    expect(document.querySelector<HTMLElement>('[data-metric="decided"]')!.dataset["none"]).toBe("false");
  });

  it("totals the attacks without claiming an untried kind was blocked", () => {
    setup();
    const foot = () => [...document.querySelectorAll("#attacks tfoot tr > *")].slice(0, 5).map((c) => c.textContent);
    expect(foot()).toEqual(["all 3 attempted kinds blocked", "3", "3", "0", "0.00"]);
    expect(document.querySelector("#attacks tfoot .alert")).toBeNull();
  });

  it("a total with an attack let through says how many kinds held, in the alert style", () => {
    setup({ window: lines([...WINDOW, BREACH]) });
    const head = document.querySelector("#attacks tfoot th")!;
    expect(head.textContent).toBe("3 of 4 attempted kinds blocked");
    expect(head.querySelector(".alert")!.textContent).toBe("3 of 4 attempted kinds blocked");
    expect(document.querySelectorAll("#attacks tfoot tr > *")[4]!.textContent).toBe("20000.00");
  });

  it("every kind attempted and blocked reads as all of them", () => {
    const all = ATTACK_KINDS.map((kind, i) => attackLine(20 + i, kind, "mcp", "denied: server undeclared", null));
    setup({ window: lines(all) });
    expect(text("#attacks tfoot th")).toBe("all 7 kinds blocked");
  });

  it("an empty window says no attack was attempted", () => {
    setup({ window: [] });
    expect(text("#attacks tfoot th")).toBe("no attacks attempted");
  });

  it("coalesces a burst of lines into one render", () => {
    document.body.innerHTML = PAGE.body.innerHTML;
    const store = new LineStore();
    const pending: (() => void)[] = [];
    mountCommand(document, store, {
      replay: "demo-1", fetchLine: async () => null, loadProvenance: async () => null, now: () => AT,
      download: () => undefined, schedule: (run) => pending.push(run),
    });
    for (const line of lines(WINDOW)) store.add(line);
    expect(pending).toHaveLength(1);
    pending[0]!();
    expect(text('[data-metric="decided"] .value')).toBe("7");
  });
});

describe("provenanceSummary", () => {
  it("an empty registry reads as empty, not as a root over 0 entries", () => {
    expect(provenanceSummary({ source: "live", replay: null, epoch: "e", window: { first: 4, last: 6, lines: 3 }, evicted: true, registry: { root: "2f".repeat(32), leaves: 0, from: "server" }, policies: null })).toBe(
      "Lines #4 to #6 (3 lines) · lines before #4 are outside this window · registry empty (server)",
    );
  });

  it("names an empty window", () => {
    expect(provenanceSummary({ source: "live", replay: null, epoch: null, window: { first: null, last: null, lines: 0 }, evicted: false, registry: null, policies: null })).toBe("No lines yet");
  });
});
