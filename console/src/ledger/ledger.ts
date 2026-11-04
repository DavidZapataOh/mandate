import type { LineStore } from "../store/store";
import { RAIL_LABEL, railOf } from "../wire/rail";
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
  if (line.source === "attack" || line.source === "deploy") {
    button.dataset.blocked = String(line.subject.blocked);
    const origin = line.source === "deploy" ? "SCENARIO" : line.subject.origin.toUpperCase();
    button.append(cell("span", "origin", origin), " ");
    name.push(origin);
  }
  const rail = railOf(line);
  if (rail !== null) {
    button.dataset.rail = rail;
    button.append(cell("span", "rail", RAIL_LABEL[rail]), " ");
    name.push(RAIL_LABEL[rail]);
  }
  // Spoken name carries its own separators so it never depends on stylesheet spacing; the words the row
  // only shows by style are parenthesised, so the visible text stays a run of the name for speech input.
  name.push(cells.time, cells.actor, sentence, `(hash) ${cells.hash}${cells.struck ? " (struck)" : ""}`, cells.verdict);
  button.setAttribute("aria-label", name.join(" · "));
  // Whitespace between flex items is not rendered; it keeps the cells separate words in the text.
  button.append(
    cell("span", "t", cells.time),
    " ",
    cell("span", "who", cells.actor),
    " ",
    cell("span", "text", sentence),
    " ",
    cell(cells.struck ? "s" : "span", "hash", cells.hash),
    " ",
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
    const active = document.activeElement;
    // Every line redraws the list; a keyboard user stays on the row they were on.
    const kept = active instanceof HTMLElement && list.contains(active) ? active.closest<HTMLElement>("[data-seq]")?.dataset.seq : undefined;
    list.dataset.mode = mode;
    list.replaceChildren(
      ...lines
        .slice(-LEDGER_ROWS)
        .reverse()
        .map((line) => row(line, mode, onOpen)),
    );
    if (kept !== undefined) list.querySelector<HTMLElement>(`button[data-seq="${kept}"]`)?.focus({ preventScroll: true });
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
