import { expect, test } from "vitest";
import { HOSTILE } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { desk, hook } from "./__fixtures__/cases";
import { cueFor } from "./cues";
import { Overlay, stageX } from "./overlay";
import { fitStage } from "./stage";
import { createWorld, pushCue, stepWorld } from "./world";

const FIT = fitStage(1440, 900);

test("a bubble shows the tag and sentence as text at its anchor times the stage scale", () => {
  const root = document.createElement("div");
  const w = createWorld(false);
  pushCue(w, cueFor(hook("NOT_MET", "scope: path escapes worktree")));
  new Overlay(root, () => {}).sync(w, FIT);
  const b = root.querySelector<HTMLButtonElement>("button.bubble")!;
  expect([b.querySelector(".tag")?.textContent, b.querySelector(".say")?.textContent]).toEqual(["Muse Code", "edit_file src/app.py · denied"]);
  expect(b.style.transform).toBe("translate(216px, 261px)");
});

test("attacker text in a bubble stays text", () => {
  const root = document.createElement("div");
  const w = createWorld(true);
  pushCue(w, cueFor(parseLine(HOSTILE)));
  stepWorld(w, 16);
  new Overlay(root, () => {}).sync(w, FIT);
  expect(root.querySelector("img")).toBeNull();
  expect(root.querySelector(".say")?.textContent).toBe('MANDATE_FIXTURE <img src=x onerror="window.pwned=1">');
  expect(root.querySelector<HTMLElement>("button.bubble")?.style.transform).toBe("translate(621px, 408px)");
});

test("expired bubbles leave the overlay and a click opens the bubble's record", () => {
  const root = document.createElement("div");
  const opened: number[] = [];
  const overlay = new Overlay(root, (seq) => opened.push(seq));
  const w = createWorld(false);
  pushCue(w, cueFor(hook("MET", "ok")));
  overlay.sync(w, FIT);
  root.querySelector<HTMLButtonElement>("button.bubble")!.click();
  expect(opened).toEqual([4]);
  stepWorld(w, 3000);
  overlay.sync(w, FIT);
  expect(root.children).toHaveLength(0);
});

test("a bubble names itself as its tag and sentence", () => {
  const root = document.createElement("div");
  const w = createWorld(false);
  pushCue(w, cueFor(hook("MET", "ok")));
  new Overlay(root, () => {}).sync(w, FIT);
  expect(root.querySelector("button.bubble")?.getAttribute("aria-label")).toBe("Muse Code: edit_file src/app.py · allowed");
});

test("on a phone's crop a walker's bubble straddles the figure but keeps 8px inside the stage", () => {
  const phone = fitStage(390, 844);
  const width = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetWidth");
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, get: () => 300 });
  try {
    const root = document.createElement("div");
    const w = createWorld(true);
    pushCue(w, cueFor(parseLine(HOSTILE)));
    stepWorld(w, 16);
    const overlay = new Overlay(root, () => {});
    overlay.sync(w, phone);
    const at = (): string => root.querySelector<HTMLElement>("button.bubble")?.style.transform ?? "";
    expect(at()).toBe("translate(15px, 272px)");
    w.walker!.x = 100;
    overlay.sync(w, phone);
    expect(at()).toBe("translate(8px, 272px)");
    w.walker!.x = 400;
    overlay.sync(w, phone);
    expect(at()).toBe("translate(82px, 272px)");
  } finally {
    if (width) Object.defineProperty(HTMLElement.prototype, "offsetWidth", width);
  }
});

function withBox<T>(width: number, height: number, run: () => T): T {
  const saved = ["offsetWidth", "offsetHeight"].map((k) => [k, Object.getOwnPropertyDescriptor(HTMLElement.prototype, k)] as const);
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, get: () => width });
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, get: () => height });
  try {
    return run();
  } finally {
    for (const [k, d] of saved) if (d) Object.defineProperty(HTMLElement.prototype, k, d);
  }
}

test("a two-line walker bubble rises so its bottom stays above the alert bar", () => {
  const small = fitStage(1280, 700);
  withBox(300, 40, () => {
    const root = document.createElement("div");
    const w = createWorld(true);
    pushCue(w, cueFor(parseLine(HOSTILE)));
    stepWorld(w, 16);
    new Overlay(root, () => {}).sync(w, small);
    // Alert top is 151 × 2 = 302; 302 - 4 - 40 = 258, above the 136 × 2 = 272 anchor.
    expect(root.querySelector<HTMLElement>("button.bubble")?.style.transform).toBe("translate(264px, 258px)");
  });
});

test("the holder's bubble at the booth stays above the TELLER sign", () => {
  withBox(200, 50, () => {
    const root = document.createElement("div");
    const w = createWorld(false);
    pushCue(w, cueFor(desk("approve", "approved")));
    new Overlay(root, () => {}).sync(w, FIT);
    // Sign top is (38 + 9) × 3 = 141; 141 - 4 - 50 = 87, above the 30 × 3 = 90 anchor.
    expect(root.querySelector<HTMLElement>('button.bubble[data-anchor="booth"]')?.style.transform).toBe("translate(588px, 87px)");
  });
});

test("a fixed tag on a cropped stage is pulled back inside it", () => {
  const wide = fitStage(1600, 1000);
  expect(wide.cropX).toBe(88);
  expect(stageX(6, 90, wide)).toBe(8);
  expect(stageX(145, 90, wide)).toBe(145 * 4 - 88);
  expect(stageX(440, 90, wide)).toBe(1600 - 8 - 90);
});
