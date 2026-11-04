import type { LineStore } from "../store/store";
import { parseLine } from "../wire/parse";
import type { ConsoleLine } from "../wire/types";

type FetchLine = (seq: number) => Promise<ConsoleLine | null>;

const show = (value: unknown): string =>
  typeof value === "string" ? value : JSON.stringify(value, null, 2);

function decision(line: ConsoleLine): string {
  if (line.event) return show(line.event);
  if (line.source === "attack") return `Decided by ${line.subject.layer}: ${line.subject.reason}`;
  return "No gate decision";
}

function blocks(line: ConsoleLine): [string, string][] {
  const f = line.forensic;
  const head: [string, string] = ["Decision", decision(line)];
  const tail: [string, string][] = [
    ["Attribution", line.meta ? show(line.meta) : "No model call"],
    ["Subject", show(line.subject)],
  ];
  if (!f) return [head, ["Canonical action (CAVA)", "Nothing reached the gate"], ...tail];
  return [
    head,
    ["Canonical action (CAVA)", show(f.cava)],
    ["Action hash", f.action_hash],
    ["Policy", show(f.policy)],
    ["Certificate claims", f.cert_claims ? show(f.cert_claims) : "No certificate issued"],
    ["Holder consent", f.consent ? show(f.consent) : "No consent presented"],
    ["Registry proof", f.registry ? show(f.registry) : "Not in the registry"],
    ["Anchor", f.anchor ?? "No anchor"],
    ["Bank transfer", f.bank ? show(f.bank) : "No money moved"],
    ...tail,
  ];
}

function button(label: string, onClick: () => void): HTMLButtonElement {
  const el = document.createElement("button");
  el.type = "button";
  el.textContent = label;
  el.addEventListener("click", onClick);
  return el;
}

/** Show every piece of evidence of a line as text. */
export function renderForensic(aside: HTMLElement, line: ConsoleLine): void {
  const heading = document.createElement("h2");
  heading.textContent = `Line #${line.seq} · ${line.source}`;
  const sections = blocks(line).map(([title, value]) => {
    const section = document.createElement("section");
    const h3 = document.createElement("h3");
    h3.textContent = title;
    const pre = document.createElement("pre");
    pre.textContent = value;
    section.append(
      h3,
      pre,
      button("Copy", () => void navigator.clipboard?.writeText(pre.textContent ?? "")),
    );
    return section;
  });
  aside.replaceChildren(
    heading,
    button("Close", () => {
      aside.hidden = true;
    }),
    ...sections,
  );
  aside.hidden = false;
}

/** Hide the drawer and drop the line it showed. */
export function closeForensic(aside: HTMLElement): void {
  aside.hidden = true;
  aside.replaceChildren();
}

/** Fetch a line the store let go from the live server; a replay never asks it. */
export function forensicFetcher(replaying: boolean, fetchImpl: typeof fetch = fetch): FetchLine {
  if (replaying) return async () => null;
  return async (seq) => {
    try {
      const resp = await fetchImpl(`/api/forensic/${seq}`);
      return resp.status === 200 ? parseLine(await resp.text()) : null;
    } catch {
      return null;
    }
  };
}

/** Open a line from the store, or from the server when the store let it go. */
export async function openForensic(
  aside: HTMLElement,
  seq: number,
  store: LineStore,
  fetchLine: FetchLine,
  decorate?: (aside: HTMLElement, line: ConsoleLine) => void,
): Promise<boolean> {
  const line = store.get(seq) ?? (await fetchLine(seq));
  if (!line) return false;
  renderForensic(aside, line);
  decorate?.(aside, line);
  return true;
}
