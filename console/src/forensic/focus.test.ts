import { beforeEach, expect, test } from "vitest";
import { ATTACK } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { renderForensic } from "./drawer";

let aside: HTMLElement;
let opener: HTMLButtonElement;

beforeEach(() => {
  document.body.innerHTML = '<ol id="ledger"><li><button type="button" data-seq="4">row</button></li></ol><aside id="forensic" hidden></aside>';
  aside = document.getElementById("forensic")!;
  opener = document.querySelector("button")!;
  opener.focus();
});

const escape = () => aside.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));

test("opening the drawer moves focus to its heading", () => {
  renderForensic(aside, parseLine(ATTACK));
  expect(document.activeElement).toBe(aside.querySelector("h2"));
});

test("Escape closes the drawer and returns focus to what opened it", () => {
  renderForensic(aside, parseLine(ATTACK));
  escape();
  expect(aside.hidden).toBe(true);
  expect(document.activeElement).toBe(opener);
});

test("closing returns focus to the same line's row when the opener was redrawn", () => {
  renderForensic(aside, parseLine(ATTACK));
  const redrawn = document.createElement("button");
  redrawn.dataset.seq = "4";
  opener.replaceWith(redrawn);
  [...aside.querySelectorAll("button")].find((b) => b.textContent === "Close")!.click();
  expect(document.activeElement).toBe(redrawn);
});

test("reopening while open keeps the first opener and one Escape closes", () => {
  delete opener.dataset.seq;
  renderForensic(aside, parseLine(ATTACK));
  renderForensic(aside, parseLine(ATTACK));
  escape();
  expect(aside.hidden).toBe(true);
  expect(document.activeElement).toBe(opener);
});

test("focus returns to the row in the opener's own list, not to a bubble of the same line", () => {
  document.body.insertAdjacentHTML("afterbegin", '<div id="overlay"><button class="bubble" data-seq="4">bubble</button></div>');
  renderForensic(aside, parseLine(ATTACK));
  const redrawn = document.createElement("button");
  redrawn.dataset.seq = "4";
  opener.replaceWith(redrawn);
  escape();
  expect(document.activeElement).toBe(redrawn);
});
