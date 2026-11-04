import { beforeEach, describe, expect, it } from "vitest";
import { refused, released } from "../scene/__fixtures__/cases";
import { LineStore } from "../store/store";
import { mountLedger } from "./ledger";
import { forensicText, gameText } from "./narrate";
import { tally } from "./tally";

describe("deploy lines in the ledger", () => {
  it.each([
    ["the release", released(), "Released ✓ MANDATE_FIXTURE Deploy api-v2 to prod-eu in 18µs"],
    [
      "the poisoned tool",
      refused("poisoned_tool", "mcp", "denied: tool undeclared"),
      "Blocked poisoned MCP tool at mcp: denied: tool undeclared",
    ],
    [
      "the stale migration",
      refused("stale_migration", "gate", "no rule matches"),
      "Blocked stale migration at gate: no rule matches",
    ],
    [
      "a refused release",
      refused("release", "gate", "stale: token expired"),
      "Blocked release at gate: stale: token expired",
    ],
    [
      "a step that got through",
      refused("poisoned_tool", "mcp", "ok: declared", { blocked: false }),
      "NOT BLOCKED: poisoned MCP tool at mcp: ok: declared",
    ],
  ])("narrates %s", (_name, line, want) => {
    expect(gameText(line)).toBe(want);
  });

  it("shows the deploy source and the deciding reason in forensic mode", () => {
    expect(forensicText(refused("stale_migration", "gate", "no rule matches"))).toBe(
      "#10 deploy NOT_MET 1be9ccd395f3 no rule matches",
    );
  });

  it("counts the release as verified and both refusals as denied", () => {
    const lines = [
      released(),
      refused("poisoned_tool", "mcp", "denied: tool undeclared", { lat_us: 9.0, seq: 10 }),
      refused("stale_migration", "gate", "no rule matches", { seq: 11 }),
    ];
    expect(tally(lines)).toEqual({ verified: 1, denied: 2, p50: "18µs" });
  });
});

describe("deploy rows", () => {
  let list: HTMLOListElement;
  let store: LineStore;

  beforeEach(() => {
    document.body.innerHTML = '<ol id="ledger"></ol>';
    list = document.getElementById("ledger") as HTMLOListElement;
    store = new LineStore();
    mountLedger(list, store, () => {});
  });

  const row = (seq: number) => {
    const b = list.querySelector<HTMLButtonElement>(`button[data-seq="${seq}"]`)!;
    return [
      b.querySelector(".origin")?.textContent,
      b.querySelector(".who")?.textContent,
      b.querySelector(".hash")?.textContent,
      b.querySelector("s.hash") !== null,
      b.querySelector(".verdict")?.textContent,
      b.dataset.outcome,
      b.dataset.blocked,
    ];
  };

  it("a released row carries the SCENARIO badge and the seal", () => {
    store.add(released());
    expect(row(9)).toEqual(["SCENARIO", "nimbus scenario", "1BE9CC", false, "VERIFIED", "pass", "false"]);
  });

  it("a refused row strikes the action it refused", () => {
    store.add(refused("poisoned_tool", "mcp", "denied: tool undeclared"));
    expect(row(10)).toEqual(["SCENARIO", "nimbus scenario", "1BE9CC", true, "DENIED", "deny", "true"]);
  });
});
