import { beforeEach, describe, expect, it } from "vitest";
import { LineStore } from "../store/store";
import { ATTACK, CONFIRM, HOSTILE_QUOTE, patch } from "../wire/__fixtures__/lines";
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

const rows = () => [...list.querySelectorAll("button")].map((b) => b.textContent);

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
      "TEMPLATE #4 attack NOT_MET cbf0720db7ba recipient differs from intent",
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
});
