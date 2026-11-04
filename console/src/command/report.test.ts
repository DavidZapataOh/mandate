import { describe, expect, it } from "vitest";
import { SERVER_BODY } from "./__fixtures__/provenance";
import { attackLine, BREACH, DEPLOY_BREACH, lines, PIPE_KIND, WINDOW } from "./__fixtures__/window";
import { computePosture } from "./posture";
import { parseProvenance, provenanceOf } from "./provenance";
import { buildReport, cell, lineCount, metricValue, reportFileName, reportJson, reportMarkdown, TILES } from "./report";

const ROOT = "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87";
const AT = Date.UTC(2026, 10, 3, 17, 0, 0);
const window = lines(WINDOW);
const live = buildReport(computePosture(window), provenanceOf(window, parseProvenance(SERVER_BODY), null), AT);

describe("reportMarkdown", () => {
  it("opens with the disclaimer and the provenance it rests on", () => {
    expect(reportMarkdown(live).split("\n").slice(0, 14)).toEqual([
      "# Mandate posture report",
      "",
      "This report maps Mandate controls to framework provisions. It is not a certification, an audit opinion or a statement of compliance.",
      "",
      "## Provenance",
      "",
      "| Field | Value |",
      "|---|---|",
      "| Generated | 2026-11-03T17:00:00.000Z |",
      "| Source | live console (server epoch MANDATE_FIXTURE-a1b2c3d4) |",
      "| Window | lines #1 to #9 (9 lines) |",
      `| Registry root | ${ROOT} |`,
      "| Registry entries | 1 (server) |",
      "| Policies served | desk v1, payments v1, nimbus v1 |",
    ]);
  });

  it("states each metric with its value", () => {
    const md = reportMarkdown(live);
    for (const want of [
      "| Actions decided | 7 |",
      "| Moved by attacks | 0.00 |",
      "| Holder consent on certified payments | 1 of 2 · 50.0% |",
      "| Gate decision time | p50 61µs · p95 90µs (5 samples) |",
      "| Decisions naming their model call | 4 of 7 · 57.1% |",
      "| payee_swap | 1 | 1 | 0 | 0.00 | gate |",
      "| amount_inflate | 0 | 0 | 0 | 0.00 | not attempted |",
      "| broker | 0 | none |",
    ]) {
      expect(md).toContain(want);
    }
  });

  it("maps every control with this window's evidence and its gap", () => {
    const rows = reportMarkdown(live).split("\n").filter((l) => /^\| (NIST AI RMF 1.0|ISO\/IEC 42001:2023|EU AI Act) \|/.test(l));
    expect(rows).toHaveLength(17);
    expect(rows[16]).toBe(
      "| EU AI Act | Article 73(1): Reporting of serious incidents by providers to the market surveillance authorities. | Attacks that were not blocked and Nimbus steps that ran when they should not are counted, and each opens its forensic record. | 0 attacks not blocked · 0 deploy steps ran when they should not | Mandate does not report to any authority. | https://eur-lex.europa.eu/eli/reg/2024/1689/oj |",
    );
  });

  it("an evicted replay window says where it starts and where it came from", () => {
    const tail = window.slice(3);
    const md = reportMarkdown(buildReport(computePosture(tail), provenanceOf(tail, null, "demo-1"), AT));
    expect(md).toContain("| Source | replay demo-1 (recorded stream) |");
    expect(md).toContain("| Window | lines #4 to #9 (6 lines); lines before #4 are outside this window |");
    expect(md).toContain("| Registry root | none in this window |");
    expect(md).toContain("| Policies served | not served |");
  });

  it("an empty window still reports, with nothing claimed", () => {
    const md = reportMarkdown(buildReport(computePosture([]), provenanceOf([], null, null), AT));
    expect(md).toContain("| Window | no lines |");
    expect(md).toContain("| Gate decision time | no gate events in this window |");
    expect(md).toContain("| Holder consent on certified payments | none in this window |");
  });

  it("wire text cannot break out of its table cell", () => {
    const pipe = lines([PIPE_KIND]);
    const md = reportMarkdown(buildReport(computePosture(pipe), provenanceOf(pipe, null, null), AT));
    expect(md).toContain("| x\\|y | 1 | 1 | 0 | 0.00 | MCP proxy |");
    expect(cell("a|b\nc\\")).toBe("a\\|b c\\\\");
  });
});

describe("lineCount", () => {
  it("reads one line in the singular", () => {
    expect([0, 1, 2].map(lineCount)).toEqual(["0 lines", "1 line", "2 lines"]);
    const one = window.slice(8);
    expect(reportMarkdown(buildReport(computePosture(one), provenanceOf(one, null, null), AT))).toContain(
      "| Window | lines #9 to #9 (1 line); lines before #9 are outside this window |",
    );
  });
});

describe("reportMarkdown stopped at", () => {
  it("an attack attempted and not blocked reads not stopped", () => {
    const w = lines([...WINDOW, BREACH]);
    const md = reportMarkdown(buildReport(computePosture(w), provenanceOf(w, null, null), AT));
    expect(md).toContain("| amount_inflate | 1 | 0 | 1 | 20000.00 | not stopped |");
  });
});

describe("empty registry", () => {
  it("says the registry is empty next to its root", () => {
    const prov = provenanceOf(window, parseProvenance(SERVER_BODY), null);
    const md = reportMarkdown(buildReport(computePosture(window), { ...prov, registry: { root: ROOT, leaves: 0, from: "server" } }, AT));
    expect(md).toContain("| Registry entries | 0, registry empty (server) |");
  });
});

describe("an attack window with one Nimbus step that ran", () => {
  const w = lines([...WINDOW, DEPLOY_BREACH]);
  const md = reportMarkdown(buildReport(computePosture(w), provenanceOf(w, parseProvenance(SERVER_BODY), null), AT));

  it("reads consistently in the tiles, the attacks table and the evidence", () => {
    expect(md).toContain("| Attacks not blocked | 0 |");
    expect(md).toContain("| Deploy steps that ran when they should not | 1 |");
    expect(md).toContain("| 3 of 3 attacks blocked · 0.00 moved |");
    expect(md).toContain("| 0 attacks not blocked · 1 deploy step ran when it should not |");
    expect(md).not.toMatch(/\| [1-9]\d* attacks not blocked/);
  });
});

describe("sample count", () => {
  it("a single latency sample reads in the singular", () => {
    expect(metricValue("latency", computePosture(window.slice(8)))).toBe("p50 90µs · p95 90µs (1 sample)");
  });
});

describe("reportJson", () => {
  it("carries the same window, metrics and the lines behind them", () => {
    const parsed = JSON.parse(reportJson(live));
    expect(reportJson(live).endsWith("}\n")).toBe(true);
    expect([parsed.report, parsed.generatedAt, parsed.provenance.registry, parsed.metrics.denied]).toEqual([
      "mandate-posture/1", "2026-11-03T17:00:00.000Z", { root: ROOT, leaves: 1, from: "server" }, { count: 4, seqs: [4, 5, 6, 8] },
    ]);
    expect(parsed.controls[0].evidence).toBe("policies served: desk v1, payments v1, nimbus v1");
  });
});

describe("reportFileName", () => {
  it("names the window it covers", () => {
    expect(reportFileName(live, "md")).toBe("mandate-posture-1-9.md");
    expect(reportFileName(buildReport(computePosture([]), provenanceOf([], null, null), AT), "json")).toBe(
      "mandate-posture-empty.json",
    );
  });
});

describe("markdown injection", () => {
  const HOSTILE = "[click](https://evil.example/x) ![i](https://evil.example/p.png) <img src=x onerror=alert(1)> `c` https://evil.example";
  const md = reportMarkdown(buildReport(computePosture(lines([attackLine(11, HOSTILE, "mcp", "denied: server undeclared", null)])), provenanceOf([], null, HOSTILE), AT));

  it("leaves no live link, image, tag or autolink from wire text", () => {
    expect(md).not.toMatch(/(?<!\\)[[\]]/);
    expect(md).not.toContain("<img");
    expect(md).not.toMatch(/<[a-z]/i);
    expect(md).not.toMatch(/(?<!\\)`/);
    expect(md).not.toContain("://evil");
    expect(md).toContain("&lt;img");
  });

  it("breaks www. and email autolinks", () => {
    const out = cell("see www.evil.com and Www.Evil.com and evil@x.com");
    expect(out).not.toMatch(/www\./i);
    expect(out).not.toContain("@");
    expect(out).toBe("see www&#46;evil.com and Www&#46;Evil.com and evil&#64;x.com");
  });

  it("keeps every table row on one line", () => {
    expect(cell("a\r\nb\nc")).toBe("a b c");
    for (const row of md.split("\n").filter((l) => l.startsWith("| "))) expect(row.endsWith("|")).toBe(true);
  });
});

describe("reportJson determinism", () => {
  it("is byte-identical for the same input and parses back to the same report", () => {
    const again = buildReport(computePosture(window), provenanceOf(window, parseProvenance(SERVER_BODY), null), AT);
    expect(reportJson(again)).toBe(reportJson(live));
    expect(JSON.parse(reportJson(live))).toEqual(JSON.parse(JSON.stringify(live)));
    expect(Object.keys(JSON.parse(reportJson(live)))).toEqual([
      "report", "generatedAt", "disclaimer", "applicability", "provenance", "metrics", "definitions", "controls",
    ]);
  });
});

describe("metricValue", () => {
  it("renders each tile", () => {
    const p = computePosture(window);
    expect(TILES.map((k) => metricValue(k, p))).toEqual([
      "7", "3", "4", "0", "0", "0.00", "1 of 2 · 50.0%", "p50 61µs · p95 90µs (5 samples)", "4 of 7 · 57.1%",
    ]);
  });
});
