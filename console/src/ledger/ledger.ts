import type { LineStore } from "../store/store";
import type { ConsoleLine } from "../wire/types";
import { cellsOf, forensicText, gameText, type Mode } from "./narrate";

export const LEDGER_ROWS = 200;

const ICONS = { pass: "verified", deny: "denied", hold: "waiting", breach: "breach", note: "noted" } as const;

function cell(tag: string, className: string, text: string): HTMLElement {
  const el = document.createElement(tag);
  el.className = className;
  el.textContent = text;
  return el;
}

function icon(outcome: keyof typeof ICONS): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#i-${ICONS[outcome]}`);
  svg.append(use);
  return svg;
}

function row(line: ConsoleLine, mode: Mode, onOpen: (seq: number) => void): HTMLLIElement {
  const item = document.createElement("li");
  const button = document.createElement("button");
  button.type = "button";
  button.dataset.seq = String(line.seq);
  button.dataset.source = line.source;
  if (line.event) button.dataset.verdict = line.event.verdict;
  const cells = cellsOf(line);
  button.dataset.outcome = cells.outcome;
  const sentence = mode === "game" ? gameText(line) : forensicText(line);
  const name: string[] = [];
  if (line.source === "attack") {
    button.dataset.blocked = String(line.subject.blocked);
    const origin = line.subject.origin.toUpperCase();
    button.append(cell("span", "origin", origin));
    name.push(origin);
  }
  // Spoken name carries its own separators so it never depends on stylesheet spacing.
  name.push(cells.time, cells.actor, sentence, `hash ${cells.hash}${cells.struck ? " struck" : ""}`, cells.verdict);
  button.setAttribute("aria-label", name.join(" · "));
  button.append(
    cell("span", "t", cells.time),
    cell("span", "who", cells.actor),
    cell("span", "text", sentence),
    cell(cells.struck ? "s" : "span", "hash", cells.hash),
    cell("span", "verdict", cells.verdict),
    icon(cells.outcome),
  );
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
