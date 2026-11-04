// @vitest-environment node
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import { beforeAll, expect, test } from "vitest";
import { WORLD_PALETTE } from "../tools/sprite.ts";
import { readColors } from "../tools/tokens.ts";

const CONSOLE = fileURLToPath(new URL("..", import.meta.url));
const REPO = join(CONSOLE, "..");
const DESIGN_MD = readFileSync(join(REPO, "DESIGN.md"), "utf8");
const hex = (n: number): string => n.toString(16).padStart(2, "0");

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  });
}

/** Every hex or rgb() colour in text, as lowercase rrggbb without alpha. */
function colours(text: string): string[] {
  const found: string[] = [];
  for (const m of text.matchAll(/#([0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})\b/g)) {
    const h = m[1]!.toLowerCase();
    found.push(h.length <= 4 ? [...h.slice(0, 3)].map((c) => c + c).join("") : h.slice(0, 6));
  }
  for (const m of text.matchAll(/rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/g)) {
    found.push([m[1], m[2], m[3]].map((v) => hex(Number(v))).join(""));
  }
  return found;
}

const ALLOWED = new Set([
  ...Object.values(readColors(DESIGN_MD)).flatMap(colours),
  ...WORLD_PALETTE.map((rgb) => rgb.map(hex).join("")),
]);

/** Colours in text that are neither a DESIGN.md token nor a world palette colour. */
const offPalette = (text: string, extra: readonly string[] = []): string[] =>
  colours(text).filter((c) => !ALLOWED.has(c) && !extra.includes(c));

const sources = (pattern: RegExp): string[] =>
  files(join(CONSOLE, "src")).filter(
    (p) => pattern.test(p) && !p.endsWith(".test.ts") && !p.endsWith(".d.ts") && !p.includes("__fixtures__"),
  );

let dist = "";

beforeAll(async () => {
  dist = mkdtempSync(join(tmpdir(), "console-brand-"));
  await build({ root: CONSOLE, configFile: join(CONSOLE, "vite.config.ts"), logLevel: "silent", build: { outDir: dist, emptyOutDir: true } });
}, 30_000);

test("the scanner catches a colour outside the palette in any notation", () => {
  expect(offPalette("a{color:#123456;background:#f6f4ee24;border-color:rgb(1 2 3 / 0.5);fill:#fff}")).toEqual([
    "123456",
    "ffffff",
    "010203",
  ]);
});

test("the built pages and stylesheets use only DESIGN.md colours and the world palette", () => {
  const built = files(dist).filter((p) => p.endsWith(".css") || p.endsWith(".html"));
  const leaks = built.flatMap((p) => offPalette(readFileSync(p, "utf8")).map((c) => `${relative(dist, p)}: ${c}`));
  expect(leaks).toEqual([]);
});

test("stylesheets and TypeScript name tokens instead of writing colours", () => {
  const literal = sources(/\.(css|ts)$/).flatMap((p) => colours(readFileSync(p, "utf8")).map((c) => `${relative(CONSOLE, p)}: ${c}`));
  expect(literal).toEqual([]);
});

test("the seal file stays on the brand palette", () => {
  const rml = readFileSync(join(CONSOLE, "rive/seal/scene.rml"), "utf8").replace(/colorValue="FF([0-9A-F]{6})"/g, 'colorValue="#$1"');
  expect(offPalette(rml)).toEqual([]);
});

test("DESIGN.md sets every type token in a brand face", () => {
  const families = [...DESIGN_MD.split(/\n---\n/)[0]!.matchAll(/fontFamily:\s*"([^",]+)/g)].map((m) => m[1]!.trim());
  expect(families.length).toBeGreaterThan(0);
  expect(families.filter((f) => !["Inter", "JetBrains Mono", "Press Start 2P"].includes(f))).toEqual([]);
});
