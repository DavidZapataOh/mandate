import { beforeEach, describe, expect, it } from "vitest";
import { LineStore } from "../store/store";
import { ATTACK, CONFIRM, HOSTILE_QUOTE, patch, SANDBOX_CONFIRM } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { LEDGER_ROWS, mountLedger } from "./ledger";

let list: HTMLOListElement;
let store: LineStore;
let opened: number[];

beforeEach(() => {
  document.body.innerHTML = '<ol id="ledger"></ol>';
  list = document.getElementById("ledger") as HTMLOListElement;
  store = new LineStore();
  opened = [];
});

const rows = () =>
  [...list.querySelectorAll("button")].map((b) =>
    [...b.querySelectorAll(".origin, .text")].map((span) => span.textContent).join(" "),
  );

describe("mountLedger", () => {
  it("shows the newest line first as a sentence", () => {
    mountLedger(list, store, (seq) => opened.push(seq));
    store.add(parseLine(CONFIRM));
    store.add(parseLine(ATTACK));
    expect(rows()).toEqual([
      "TEMPLATE Blocked payee swap at model->gate: recipient differs from intent",
      "Paid ✓ MANDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) from checking-881 in 61µs",
    ]);
    const first = list.querySelector("button")!;
    expect([first.dataset.seq, first.dataset.verdict, first.dataset.blocked]).toEqual([
      "4",
      "NOT_MET",
      "true",
    ]);
  });

  it("labels model-planned attacks", () => {
    mountLedger(list, store, () => {});
    store.add(parseLine(patch(ATTACK, {}, { origin: "model" })));
    expect(rows()[0]).toMatch(/^MODEL /);
  });

  it("switches every row to forensic text and back", () => {
    const ledger = mountLedger(list, store, () => {});
    store.add(parseLine(ATTACK));
    ledger.setMode("forensic");
    expect(rows()).toEqual([
      "TEMPLATE #4 attack NOT_MET 89f0357807b9 recipient differs from intent",
    ]);
    expect(list.dataset.mode).toBe("forensic");
    ledger.setMode("game");
    expect(rows()[0]).toMatch(/Blocked payee swap/);
  });

  it("opens the clicked line", () => {
    mountLedger(list, store, (seq) => opened.push(seq));
    store.add(parseLine(ATTACK));
    list.querySelector("button")!.click();
    expect(opened).toEqual([4]);
  });

  it("renders a hostile recipient as text", () => {
    mountLedger(list, store, () => {});
    store.add(parseLine(HOSTILE_QUOTE));
    expect(rows()[0]).toContain("<img/src=x/onerror=window.pwned=1>");
    expect(list.querySelector("img")).toBeNull();
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  });

  it("caps the rows it draws", () => {
    mountLedger(list, store, () => {});
    for (let seq = 1; seq <= LEDGER_ROWS + 5; seq += 1) store.add(parseLine(patch(ATTACK, { seq })));
    const buttons = list.querySelectorAll("button");
    expect(buttons).toHaveLength(LEDGER_ROWS);
    expect(buttons[0]!.dataset.seq).toBe(String(LEDGER_ROWS + 5));
  });

  it("labels every payment with the rail that moved it", () => {
    mountLedger(list, store, () => {});
    for (const text of [CONFIRM, ATTACK, SANDBOX_CONFIRM]) store.add(parseLine(text));
    const buttons = [...list.querySelectorAll("button")];
    expect(buttons.map((b) => b.querySelector(".rail")?.textContent ?? null)).toEqual([
      "SANDBOX",
      null,
      "SIMULATED",
    ]);
    expect(buttons.map((b) => b.dataset["rail"] ?? null)).toEqual(["sandbox", null, "simulated"]);
    // The badge follows the sentence, so the time and actor columns start alike on every row.
    expect([...buttons[2]!.children].map((c) => c.getAttribute("class"))).toEqual(["t", "who", "text", "rail", "hash", "verdict", "icon"]);
  });

  it("keeps the rows it already drew when a line arrives", () => {
    mountLedger(list, store, () => {});
    for (const seq of [1, 2, 3]) store.add(parseLine(patch(ATTACK, { seq })));
    const before = [...list.querySelectorAll("button")];
    store.add(parseLine(patch(ATTACK, { seq: 4 })));
    const after = [...list.querySelectorAll("button")];
    expect(after.map((b) => b.dataset.seq)).toEqual(["4", "3", "2", "1"]);
    after.slice(1).forEach((button, i) => expect(button).toBe(before[i]));
  });

  it("redraws every row when the mode changes", () => {
    const ledger = mountLedger(list, store, () => {});
    store.add(parseLine(patch(ATTACK, { seq: 1 })));
    const before = list.querySelector("button");
    ledger.setMode("forensic");
    expect(list.querySelector("button")).not.toBe(before);
  });
});
