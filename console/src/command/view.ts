import { openForensic } from "../forensic/drawer";
import { forensicText, gameText } from "../ledger/narrate";
import { attackLabel } from "../scene/cues";
import type { LineStore } from "../store/store";
import type { ConsoleLine } from "../wire/types";
import { computePosture, counted, DEFINITIONS, formatCents, LABELS, type Posture } from "./posture";
import { type Provenance, provenanceOf, type ServerProvenance } from "./provenance";
import { attackTotal, buildReport, latencyParts, lineCount, metricValue, NOT_STOPPED, reportFileName, reportJson, reportMarkdown, stoppedAtParts, TILES } from "./report";
import { APPLICABILITY, CONTROLS, DISCLAIMER, evidenceText, registryText } from "./standards";

export interface CommandDeps {
  readonly replay: string | null;
  fetchLine(seq: number): Promise<ConsoleLine | null>;
  loadProvenance(): Promise<ServerProvenance | null>;
  now(): number;
  later(run: () => void, ms: number): void;
  download(name: string, mime: string, text: string): void;
  schedule(run: () => void): void;
}

/** The server is asked again at most this often while lines arrive. */
const REFRESH_MS = 1000;

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
    case "stepsRan": return p.stepsRan.seqs;
    // The sum runs over every attack line, so every attack line is behind it.
    case "moved": return p.attacks.flatMap((a) => a.seqs).sort((a, b) => a - b);
    // A share is drilled to its whole, so the lines lacking the part are visible too.
    case "consent": return p.consent.certified.seqs;
    case "attribution": return p.decided.seqs;
    case "latency": return p.latency.seqs;
    case "rails": return p.rails.flatMap((r) => r.seqs).sort((a, b) => a - b);
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

  const columns = [...doc.querySelectorAll("#controls thead th")].map((th) => th.textContent ?? "");
  must("#provisions").textContent = counted(CONTROLS.length, "provision", "provisions");
  const register = must<HTMLElement>("#controls .register");
  const markEnd = (): void => {
    const end = String(register.scrollTop + register.clientHeight >= register.scrollHeight - 1);
    if (register.dataset["atEnd"] !== end) register.dataset["atEnd"] = end;
  };
  register.addEventListener("scroll", markEnd, { passive: true });

  const footRow = make("tr");
  const footHead = make("th");
  footHead.scope = "row";
  const footCells = [make("td"), make("td"), make("td"), make("td")];
  footCells[3]!.className = "moved";
  footRow.append(footHead, ...footCells, make("td"), make("td"));
  must("#attacks tfoot").replaceChildren(footRow);

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
    // Each cell names its column, so a narrow screen can stack the row and keep every value labelled.
    [...tr.children].forEach((cell, i) => {
      (cell as HTMLElement).dataset["label"] = columns[i] ?? "";
    });
    return { control: c, evidence };
  });
  must("#controls tbody").replaceChildren(...controlRows.map((r) => r.evidence.parentElement!));

  const renderValue = (key: Tile, el: HTMLElement, value: string, posture: Posture): void => {
    const parts = key === "latency" ? latencyParts(posture) : null;
    if (parts !== null) {
      const sub = make("span", parts[1]);
      sub.className = "sub";
      el.replaceChildren(parts[0], " ", sub);
      return;
    }
    const at = value.indexOf(" · ");
    if ((key === "consent" || key === "attribution") && at > 0) {
      // Count and share are each kept whole, so a wrapped line never ends on the dot.
      const count = make("span", value.slice(0, at));
      const share = make("span", value.slice(at + 1));
      count.className = share.className = "part";
      el.replaceChildren(count, " ", share);
      return;
    }
    el.textContent = value;
  };

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
      if (tile.value.textContent !== value) renderValue(key, tile.value, value, posture);
      const none = String(value.endsWith("in this window"));
      if (tile.article.dataset["none"] !== none) tile.article.dataset["none"] = none;
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

    const total = attackTotal(posture);
    if (footHead.textContent !== total.text) {
      if (total.held) footHead.textContent = total.text;
      else {
        const alert = make("span", total.text);
        alert.className = "alert";
        footHead.replaceChildren(alert);
      }
    }
    [total.attempts, total.blocked, total.breaches].forEach((n, i) => setText(footCells[i]!, String(n)));
    setText(footCells[3]!, formatCents(total.movedCents));
    footRow.dataset["breach"] = String(!total.held);

    for (const { control, evidence } of controlRows) setText(evidence, evidenceText(control.evidence, posture, prov));
    markEnd();

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
  let lastRead = Number.NEGATIVE_INFINITY;
  let waiting = false;
  const refresh = async (): Promise<void> => {
    if (deps.replay !== null) return;
    const id = ++reads;
    lastRead = deps.now();
    const next = await deps.loadProvenance();
    if (id !== reads) return;
    server = next;
    request();
  };

  // The registry grows with every payment, so lines changing means the server's value may be stale.
  const sync = (lines: readonly ConsoleLine[]): void => {
    if (deps.replay !== null) return;
    if (lines.length === 0) {
      // A new run: the old run's registry and policies no longer describe anything.
      server = null;
      reads += 1;
      void refresh();
      return;
    }
    if (waiting) return;
    const wait = lastRead + REFRESH_MS - deps.now();
    if (wait <= 0) return void refresh();
    waiting = true;
    deps.later(() => {
      waiting = false;
      void refresh();
    }, wait);
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

  store.subscribe((lines) => {
    sync(lines);
    request();
  });
  render();
  void refresh();
  return { exportReport };
}
