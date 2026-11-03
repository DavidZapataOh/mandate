import type { LineStore } from "../store/store";
import type { ConsoleLine } from "../wire/types";
import { forensicText, gameText, type Mode } from "./narrate";

export const LEDGER_ROWS = 200;

function row(line: ConsoleLine, mode: Mode, onOpen: (seq: number) => void): HTMLLIElement {
  const item = document.createElement("li");
  const button = document.createElement("button");
  button.type = "button";
  button.dataset.seq = String(line.seq);
  button.dataset.source = line.source;
  if (line.event) button.dataset.verdict = line.event.verdict;
  if (line.source === "attack") {
    button.dataset.blocked = String(line.subject.blocked);
    const origin = document.createElement("span");
    origin.className = "origin";
    origin.textContent = line.subject.origin.toUpperCase();
    button.append(origin, " ");
  }
  const text = document.createElement("span");
  text.className = "text";
  text.textContent = mode === "game" ? gameText(line) : forensicText(line);
  button.append(text);
  button.addEventListener("click", () => onOpen(line.seq));
  item.append(button);
  return item;
}

/** Render the newest lines first and follow the store. */
export function mountLedger(
  list: HTMLElement,
  store: LineStore,
  onOpen: (seq: number) => void,
): { setMode(mode: Mode): void } {
  let mode: Mode = "game";
  const render = (lines: readonly ConsoleLine[]): void => {
    list.dataset.mode = mode;
    list.replaceChildren(
      ...lines
        .slice(-LEDGER_ROWS)
        .reverse()
        .map((line) => row(line, mode, onOpen)),
    );
  };
  store.subscribe(render);
  render(store.lines());
  return {
    setMode(next) {
      mode = next;
      render(store.lines());
    },
  };
}
