import { beforeEach, expect, test } from "vitest";
import { LineStore } from "../store/store";
import { ATTACK, CONFIRM, HOSTILE, patch } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { mountLedger } from "./ledger";

let list: HTMLOListElement;
let store: LineStore;

beforeEach(() => {
  document.body.innerHTML = '<ol id="ledger"></ol>';
  list = document.getElementById("ledger") as HTMLOListElement;
  store = new LineStore();
  mountLedger(list, store, () => {});
});

const cells = (seq: number) => {
  const b = list.querySelector<HTMLButtonElement>(`button[data-seq="${seq}"]`)!;
  return {
    t: b.querySelector(".t")?.textContent,
    who: b.querySelector(".who")?.textContent,
    hash: b.querySelector(".hash")?.textContent,
    struck: b.querySelector("s.hash") !== null,
    verdict: b.querySelector(".verdict")?.textContent,
    icon: b.querySelector("use")?.getAttribute("href"),
    outcome: b.dataset.outcome,
  };
};

test("a denied row strikes the action hash it refused and says DENIED with the stamp glyph", () => {
  store.add(parseLine(ATTACK));
  expect(cells(4)).toEqual({ t: "08:16:40", who: "template attack", hash: "CBF072", struck: true, verdict: "DENIED", icon: "#i-denied", outcome: "deny" });
});

test("a verified row carries the seal glyph and nothing is struck", () => {
  store.add(parseLine(CONFIRM));
  expect(cells(3)).toEqual({ t: "08:16:40", who: "agent", hash: "3A531D", struck: false, verdict: "VERIFIED", icon: "#i-verified", outcome: "pass" });
});

test("a refusal outside the gate is timed by its canonical action, or shows no time when nothing reached the gate", () => {
  store.add(parseLine(patch(ATTACK, { event: null }, { attack: "replay", layer: "bank", reason: "replay: jti consumed" })));
  store.add(parseLine(HOSTILE));
  expect([cells(4).t, cells(4).hash]).toEqual(["08:16:40", "CBF072"]);
  expect([cells(7).t, cells(7).who, cells(7).hash]).toEqual(["--:--:--", "open-weights attacker", "------"]);
});

test("a breach is marked NOT BLOCKED and never struck", () => {
  store.add(parseLine(patch(ATTACK, {}, { blocked: false, moved_cents: 20000, reason: "ok: executed" })));
  expect([cells(4).verdict, cells(4).struck, cells(4).icon]).toEqual(["NOT BLOCKED", false, "#i-breach"]);
});

test("each row names itself in words without relying on stylesheet spacing", () => {
  store.add(parseLine(CONFIRM));
  store.add(parseLine(ATTACK));
  const name = (seq: number) => list.querySelector(`button[data-seq="${seq}"]`)?.getAttribute("aria-label");
  expect(name(4)).toBe("TEMPLATE · 08:16:40 · template attack · Blocked payee swap at model->gate: recipient differs from intent · hash CBF072 struck · DENIED");
  expect(name(3)).toBe("08:16:40 · agent · Paid ✓ MANDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) from checking-881 in 61µs · hash 3A531D · VERIFIED");
});
