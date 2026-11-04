import { openForensic } from "../forensic/drawer";
import { forensicText, gameText } from "../ledger/narrate";
import { attackLabel } from "../scene/cues";
import type { LineStore } from "../store/store";
import type { ConsoleLine } from "../wire/types";
import { computePosture, DEFINITIONS, formatCents, LABELS, type Posture } from "./posture";
import { type Provenance, provenanceOf, type ServerProvenance } from "./provenance";
import { buildReport, lineCount, metricValue, NOT_STOPPED, reportFileName, reportJson, reportMarkdown, stoppedAtParts, TILES } from "./report";
import { APPLICABILITY, CONTROLS, DISCLAIMER, evidenceText, registryText } from "./standards";

export interface CommandDeps {
  readonly replay: string | null;
  fetchLine(seq: number): Promise<ConsoleLine | null>;
  loadProvenance(): Promise<ServerProvenance | null>;
  now(): number;
  download(name: string, mime: string, text: string): void;
  schedule(run: () => void): void;
}

type Tile = (typeof TILES)[number];

type Drill =
  | { readonly by: "metric"; readonly key: Tile }
  | { readonly by: "attack"; readonly key: string }
  | { readonly by: "layer"; readonly key: string };

interface RowView {
  readonly tr: HTMLTableRowElement;
  readonly cells: readonly HTMLElement[];
  readonly drill: HTMLButtonElement;
}

/** One line naming the window, where it starts and the registry root it rests on. */
export function provenanceSummary(p: Provenance): string {
  const parts: string[] = [];
  if (p.replay !== null) parts.push(`Replay ${p.replay}`);
  const { first, last, lines } = p.window;
  parts.push(first === null || last === null ? "No lines yet" : `Lines #${first} to #${last} (${lineCount(lines)})`);
  if (p.evicted) parts.push(`lines before #${first} are outside this window`);
  if (p.registry !== null) parts.push(registryText(p.registry));
  return parts.join(" · ");
}

function metricSeqs(key: Tile, p: Posture): readonly number[] {
  switch (key) {
    case "decided": return p.decided.seqs;
    case "verified": return p.verified.seqs;
    case "denied": return p.denied.seqs;
    case "breaches": return p.breaches.seqs;
    // The sum runs over every attack line, so every attack line is behind it.
    case "moved": return p.attacks.flatMap((a) => a.seqs).sort((a, b) => a - b);
    // A share is drilled to its whole, so the lines lacking the part are visible too.
    case "consent": return p.consent.certified.seqs;
    case "attribution": return p.decided.seqs;
    case "latency": return p.latency.seqs;
  }
}

function drillSeqs(d: Drill, p: Posture): readonly number[] {
  if (d.by === "metric") return metricSeqs(d.key, p);
  const rows = d.by === "attack" ? p.attacks.filter((a) => a.kind === d.key) : p.layers.filter((l) => l.layer === d.key);
  return rows[0]?.seqs ?? [];
}

function drillLabel(d: Drill): string {
  if (d.by === "metric") return LABELS[d.key];
  return d.by === "attack" ? attackLabel(d.key) : `Denied at the ${d.key}`;
}

const showText = (n: number): string => `Show the ${lineCount(n)}`;

/** Put `nodes` in `parent` in order, moving only what changed so focus survives a live update. */
function reconcile(parent: Element, nodes: readonly Element[]): void {
  let cursor = parent.firstElementChild;
  for (const node of nodes) {
    if (node === cursor) {
      cursor = cursor.nextElementSibling;
      continue;
    }
    parent.insertBefore(node, cursor);
  }
  while (cursor) {
    const next = cursor.nextElementSibling;
    cursor.remove();
    cursor = next;
  }
}

function setText(el: Element, value: string): void {
  if (el.textContent !== value) el.textContent = value;
}

/** Render the Command page over a store, re-rendering on every change, with drill and export. */
export function mountCommand(doc: Document, store: LineStore, deps: CommandDeps): { exportReport(ext: "md" | "json"): Promise<void> } {
  const must = <T extends Element>(sel: string): T => {
    const el = doc.querySelector<T>(sel);
    if (!el) throw new Error(`missing ${sel}`);
    return el;
  };
  const make = <K extends keyof HTMLElementTagNameMap>(tag: K, text?: string): HTMLElementTagNameMap[K] => {
    const el = doc.createElement(tag);
    if (text !== undefined) el.textContent = text;
    return el;
  };
  const drillButton = (onClick: () => void): HTMLButtonElement => {
    const b = make("button");
    b.type = "button";
    b.className = "drill";
    b.addEventListener("click", onClick);
    return b;
  };

  const provenanceEl = must<HTMLElement>("#provenance");
  const attackBody = must<HTMLElement>("#attacks tbody");
  const layerBody = must<HTMLElement>("#layers tbody");
  const drillSection = must<HTMLElement>("#drill");
  const drillTitle = must<HTMLElement>("#drill-title");
  const drillStatus = must<HTMLElement>("#drill-status");
  const drillList = must<HTMLElement>("#drill ol");
  const aside = must<HTMLElement>("#forensic");

  must("#attacks .definition").textContent = DEFINITIONS.attacks;
  must("#layers .definition").textContent = DEFINITIONS.layers;
  must("#disclaimer").textContent = DISCLAIMER;
  must("#applicability").textContent = APPLICABILITY;
  drillTitle.tabIndex = -1;

  let server: ServerProvenance | null = null;
  let drill: Drill | null = null;
  let pending = false;

  const open = (next: Drill): void => {
    drill = next;
    render();
    drillSection.hidden = false;
    // The drill itself is not live (a busy stream would re-announce it); only opening it is said.
    drillStatus.textContent = `Opened ${drillTitle.textContent ?? ""}`;
    drillTitle.focus();
  };

  const tiles = new Map<Tile, { article: HTMLElement; value: HTMLElement; drill: HTMLButtonElement }>();
  must("#tiles").replaceChildren(
    ...TILES.map((key) => {
      const article = make("article");
      article.dataset["metric"] = key;
      const h3 = make("h3", LABELS[key]);
      h3.id = `metric-${key}`;
      article.setAttribute("aria-labelledby", h3.id);
      const value = make("p");
      value.className = "value";
      const details = make("details");
      const definition = make("p", DEFINITIONS[key]);
      definition.className = "definition";
      details.append(make("summary", "Definition"), definition);
      const button = drillButton(() => open({ by: "metric", key }));
      button.setAttribute("aria-describedby", h3.id);
      article.append(h3, value, details, button);
      tiles.set(key, { article, value, drill: button });
      return article;
    }),
  );

  const row = (attr: "kind" | "layer", key: string, cellCount: number, onDrill: () => void): RowView => {
    const tr = make("tr");
    tr.dataset[attr] = key;
    const head = make("th");
    head.scope = "row";
    const cells: HTMLElement[] = [head];
    for (let i = 1; i < cellCount; i++) cells.push(make("td"));
    const drillCell = make("td");
    const button = drillButton(onDrill);
    drillCell.append(button);
    tr.append(...cells, drillCell);
    return { tr, cells, drill: button };
  };
  const attackRows = new Map<string, RowView>();
  const layerRows = new Map<string, RowView>();

  const controlRows = CONTROLS.map((c) => {
    const tr = make("tr");
    tr.dataset["control"] = `${c.framework} ${c.id}`;
    const provision = make("th", `${c.id}: ${c.title}`);
    provision.scope = "row";
    const evidence = make("td");
    evidence.className = "evidence";
    const link = make("a", "source");
    link.href = c.source;
    link.rel = "noreferrer";
    const source = make("td");
    source.append(link);
    tr.append(make("td", c.framework), provision, make("td", c.mandate), evidence, make("td", c.gap), source);
    return { control: c, evidence };
  });
  must("#controls tbody").replaceChildren(...controlRows.map((r) => r.evidence.parentElement!));

  const renderStopped = (td: HTMLElement, parts: readonly string[]): void => {
    if (td.textContent === parts.join(", ")) return;
    const nodes: (string | HTMLElement)[] = [];
    parts.forEach((part, i) => {
      if (i > 0) nodes.push(", ");
      if (part !== NOT_STOPPED) return void nodes.push(part);
      const alert = make("span", part);
      alert.className = "alert";
      nodes.push(alert);
    });
    td.replaceChildren(...nodes);
  };

  let drillItems = new Map<number, { line: ConsoleLine; li: HTMLLIElement }>();
  const empty = make("li", "No lines in this window");

  const drillItem = (line: ConsoleLine): HTMLLIElement => {
    const cached = drillItems.get(line.seq);
    if (cached?.line === line) return cached.li;
    const li = make("li");
    const button = make("button");
    button.type = "button";
    button.dataset["seq"] = String(line.seq);
    const sentence = make("span", gameText(line));
    sentence.className = "sentence";
    const mono = make("span", forensicText(line));
    mono.className = "row";
    button.append(sentence, mono);
    button.addEventListener("click", () => void openForensic(aside, line.seq, store, deps.fetchLine));
    li.append(button);
    return li;
  };

  const renderDrill = (d: Drill, posture: Posture): void => {
    const seqs = drillSeqs(d, posture);
    setText(drillTitle, `${drillLabel(d)} · ${lineCount(seqs.length)}`);
    const next = new Map<number, { line: ConsoleLine; li: HTMLLIElement }>();
    for (let i = seqs.length - 1; i >= 0; i--) {
      const line = store.get(seqs[i]!);
      if (line) next.set(line.seq, { line, li: drillItem(line) });
    }
    drillItems = next;
    reconcile(drillList, next.size === 0 ? [empty] : [...next.values()].map((x) => x.li));
  };

  function render(): void {
    const lines = store.lines();
    const posture = computePosture(lines);
    const prov = provenanceOf(lines, server, deps.replay);
    setText(provenanceEl, provenanceSummary(prov));

    for (const [key, tile] of tiles) {
      const value = metricValue(key, posture);
      setText(tile.value, value);
      const zero = String(value === "0" || value === "0.00");
      if (tile.article.dataset["zero"] !== zero) tile.article.dataset["zero"] = zero;
      setText(tile.drill, showText(metricSeqs(key, posture).length));
    }

    reconcile(attackBody, posture.attacks.map((a) => {
      let view = attackRows.get(a.kind);
      if (!view) {
        view = row("kind", a.kind, 6, () => open({ by: "attack", key: a.kind }));
        attackRows.set(a.kind, view);
      }
      const values = [
        attackLabel(a.kind), String(a.attempts), String(a.blocked), String(a.breaches), formatCents(a.movedCents),
      ];
      values.forEach((v, i) => setText(view.cells[i]!, v));
      renderStopped(view.cells[5]!, stoppedAtParts(a));
      view.tr.dataset["breach"] = String(a.breaches > 0);
      setText(view.drill, showText(a.seqs.length));
      return view.tr;
    }));

    reconcile(layerBody, posture.layers.map((l) => {
      let view = layerRows.get(l.layer);
      if (!view) {
        view = row("layer", l.layer, 3, () => open({ by: "layer", key: l.layer }));
        layerRows.set(l.layer, view);
      }
      const kinds = l.kinds.length === 0 ? "none" : l.kinds.map(attackLabel).join(", ");
      [l.layer, String(l.denials), kinds].forEach((v, i) => setText(view.cells[i]!, v));
      setText(view.drill, showText(l.seqs.length));
      return view.tr;
    }));

    for (const { control, evidence } of controlRows) setText(evidence, evidenceText(control.evidence, posture, prov));

    if (drill !== null) renderDrill(drill, posture);
  }

  const request = (): void => {
    if (pending) return;
    pending = true;
    deps.schedule(() => {
      pending = false;
      render();
    });
  };

  // Only the newest read may land: an older answer would roll the registry root back.
  let reads = 0;
  const refresh = async (): Promise<void> => {
    if (deps.replay !== null) return;
    const id = ++reads;
    const next = await deps.loadProvenance();
    if (id !== reads) return;
    server = next;
    request();
  };

  must("#export-md").addEventListener("click", () => void exportReport("md"));
  must("#export-json").addEventListener("click", () => void exportReport("json"));

  async function exportReport(ext: "md" | "json"): Promise<void> {
    await refresh();
    const lines = store.lines();
    const report = buildReport(computePosture(lines), provenanceOf(lines, server, deps.replay), deps.now());
    const [mime, text] = ext === "md" ? ["text/markdown", reportMarkdown(report)] : ["application/json", reportJson(report)];
    deps.download(reportFileName(report, ext), mime, text);
  }

  store.subscribe(request);
  render();
  void refresh();
  return { exportReport };
}
