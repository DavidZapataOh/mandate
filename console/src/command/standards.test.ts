import { describe, expect, it } from "vitest";
import { SERVER_BODY, SERVER_BODY_BANK } from "./__fixtures__/provenance";
import { BREACH, DEPLOY_BREACH, lines, WINDOW } from "./__fixtures__/window";
import { ATTACK_KINDS, computePosture } from "./posture";
import { parseProvenance, provenanceOf } from "./provenance";
import { APPLICABILITY, CONTROLS, DISCLAIMER, evidenceText, type EvidenceKey } from "./standards";

const window = lines(WINDOW);
const posture = computePosture(window);
const live = provenanceOf(window, parseProvenance(SERVER_BODY), null);
const bare = provenanceOf([], null, null);

describe("evidenceText of the bank", () => {
  it("names the bank's own list", () => {
    expect(evidenceText("bank", posture, provenanceOf(window, parseProvenance(SERVER_BODY_BANK), null))).toBe(
      "bank lists 3 transfers since 2027-01-15T08:16:40Z: 3 with a certificate and a sealed entry, 0 without; 0 sealed payments missing at the bank",
    );
  });

  it("says when the bank could not be asked, in a replay and without the server", () => {
    const bank = JSON.parse(SERVER_BODY_BANK).bank;
    const down = parseProvenance(JSON.stringify({ ...JSON.parse(SERVER_BODY), bank: { ...bank, transfers: 0, certified: 0, error: "bank: unavailable" } }));
    expect([
      evidenceText("bank", posture, provenanceOf(window, down, null)),
      evidenceText("bank", posture, provenanceOf(window, null, "demo-1")),
      evidenceText("bank", posture, bare),
    ]).toEqual(["not checked: bank: unavailable · 2027-01-15T08:20:00Z", "not reconciled in a replay", "server provenance unavailable"]);
  });

  it("names every intent paid twice and every stored row it could not read", () => {
    const bank = JSON.parse(SERVER_BODY_BANK).bank;
    const twice = parseProvenance(JSON.stringify({
      ...JSON.parse(SERVER_BODY), bank: { ...bank, paid_twice: ["i:000001 -> t2 + t1"], unreadable: ["receipt t9"] },
    }));
    expect(evidenceText("bank", posture, provenanceOf(window, twice, null))).toBe(
      "bank lists 3 transfers since 2027-01-15T08:16:40Z: 3 with a certificate and a sealed entry, 0 without; 0 sealed payments missing at the bank; paid twice: i:000001 -> t2 + t1; not read: receipt t9",
    );
  });
});

describe("evidenceText", () => {
  it.each<[EvidenceKey, string]>([
    ["decided", "7 actions decided"],
    ["verified", "3 verified"],
    ["denied", "4 denied before execution"],
    ["breaches", "0 attacks not blocked · 0 deploy steps ran when they should not"],
    ["attacks", "3 of 3 attacks blocked · 0.00 moved"],
    ["consent", "certified payments with holder consent: 1 of 2 · 50.0%"],
    ["attribution", "decisions naming their model call: 4 of 7 · 57.1%"],
    ["rails", "verified payments by rail: SIMULATED 2"],
    ["bank", "not reconciled yet"],
    ["registry", "registry root 70566024e09c9a9e over 1 entry (server)"],
    ["policies", "policies served: desk v1, payments v1, nimbus v1"],
  ])("%s reads %s", (key, want) => {
    expect(evidenceText(key, posture, live)).toBe(want);
  });

  it("an empty registry reads as empty", () => {
    const empty = { ...live, registry: { root: "2f".repeat(32), leaves: 0, from: "server" } };
    expect(evidenceText("registry", posture, empty)).toBe("registry empty (server)");
  });

  it("a breach shows as money moved, never as all blocked", () => {
    const p = computePosture(lines([...WINDOW, BREACH]));
    expect(evidenceText("attacks", p, live)).toBe("3 of 4 attacks blocked · 20000.00 moved");
  });

  it("an attack window with one Nimbus step that ran reads the same in every cell", () => {
    const w = lines([...WINDOW, DEPLOY_BREACH]);
    const p = computePosture(w);
    const prov = provenanceOf(w, parseProvenance(SERVER_BODY), null);
    expect(evidenceText("attacks", p, prov)).toBe("3 of 3 attacks blocked · 0.00 moved");
    expect(evidenceText("breaches", p, prov)).toBe("0 attacks not blocked · 1 deploy step ran when it should not");
  });

  it("reads in the singular when there is one", () => {
    const one = lines([WINDOW[3]!]);
    const p = computePosture(one);
    const prov = provenanceOf(one, null, null);
    expect(evidenceText("decided", p, prov)).toBe("1 action decided");
    expect(evidenceText("attacks", p, prov)).toBe("1 of 1 attack blocked · 0.00 moved");
    expect(evidenceText("breaches", computePosture(lines([BREACH])), prov)).toBe("1 attack not blocked · 0 deploy steps ran when they should not");
  });

  it("GOVERN 1.4 names only the policies actually served", () => {
    const c = CONTROLS.find((x) => x.id === "GOVERN 1.4")!;
    expect(c.mandate).toContain("the desk, payments and Nimbus rules in force are served with each report");
    expect(c.mandate).toContain("Muse Code hook lines name their policy id only");
  });

  it("an empty window says what is missing", () => {
    const p = computePosture([]);
    expect(["registry", "policies", "consent"].map((k) => evidenceText(k as EvidenceKey, p, bare))).toEqual([
      "no registry root in this window",
      "policies not served in this window",
      "certified payments with holder consent: none in this window",
    ]);
  });
});

describe("CONTROLS", () => {
  it("never claims certification or compliance, and every row states a gap", () => {
    for (const c of CONTROLS) {
      expect(`${c.title} ${c.mandate} ${c.gap}`).not.toMatch(/\bcomplian(t|ce)\b|\bcertification\b|\bcertified (by|to|against)\b/i);
      expect(c.gap.length).toBeGreaterThan(0);
      expect(c.source.startsWith("https://")).toBe(true);
    }
  });

  it("the attack gap names as many templates as Command has attack kinds", () => {
    const gaps = new Set(CONTROLS.filter((c) => c.evidence === "attacks").map((c) => c.gap));
    expect([...gaps]).toEqual(["Seven fixed attack templates are a regression check, not a full adversarial evaluation."]);
    expect(ATTACK_KINDS).toHaveLength(7);
  });

  it("cites the three frameworks in report order", () => {
    expect(CONTROLS.map((c) => `${c.framework} ${c.id}`)).toEqual([
      "NIST AI RMF 1.0 GOVERN 1.4",
      "NIST AI RMF 1.0 MAP 3.5",
      "NIST AI RMF 1.0 MEASURE 2.4",
      "NIST AI RMF 1.0 MEASURE 2.7",
      "NIST AI RMF 1.0 MANAGE 2.4",
      "NIST AI RMF 1.0 MANAGE 4.3",
      "ISO/IEC 42001:2023 Annex A.6.2.6",
      "ISO/IEC 42001:2023 Annex A.6.2.8",
      "ISO/IEC 42001:2023 Annex A.8.4",
      "ISO/IEC 42001:2023 Annex A.9.2",
      "ISO/IEC 42001:2023 Annex A.10.3",
      "EU AI Act Article 12(1)",
      "EU AI Act Article 14(4)(d)-(e)",
      "EU AI Act Article 15(5)",
      "EU AI Act Article 26(5)",
      "EU AI Act Article 26(6)",
      "EU AI Act Article 73(1)",
    ]);
  });

  it("never uses the words complies, compliant or certified in a row or its evidence", () => {
    const texts = CONTROLS.flatMap((c) => [c.title, c.mandate, c.gap, evidenceText(c.evidence, posture, live)]);
    for (const t of texts) expect(t).not.toMatch(/\bcomplies\b|\bcompliant\b/i);
    for (const c of CONTROLS) expect(`${c.title} ${c.mandate} ${c.gap}`).not.toMatch(/\bcertified\b/i);
  });

  it("states the disclaimer and applicability", () => {
    expect(DISCLAIMER).toBe("This report maps Mandate controls to framework provisions. It is not a certification, an audit opinion or a statement of compliance.");
    expect(APPLICABILITY).toContain("determination, and Mandate does not make it.");
  });
});
