import { expect, test } from "vitest";
import { LineStore } from "../store/store";
import { ATTACK, CONFIRM } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { mountLedger } from "./ledger";

test("a new line keeps keyboard focus on the row the user was on", () => {
  document.body.innerHTML = '<ol id="ledger"></ol>';
  const list = document.getElementById("ledger")!;
  const store = new LineStore();
  mountLedger(list, store, () => undefined);
  store.add(parseLine(CONFIRM));
  list.querySelector<HTMLButtonElement>('button[data-seq="3"]')!.focus();
  store.add(parseLine(ATTACK));
  expect((document.activeElement as HTMLElement).dataset.seq).toBe("3");
});

test("a new line does not steal focus that was outside the ledger", () => {
  document.body.innerHTML = '<button id="elsewhere" type="button">x</button><ol id="ledger"></ol>';
  const list = document.getElementById("ledger")!;
  const store = new LineStore();
  mountLedger(list, store, () => undefined);
  document.getElementById("elsewhere")!.focus();
  store.add(parseLine(ATTACK));
  expect(document.activeElement!.id).toBe("elsewhere");
});
