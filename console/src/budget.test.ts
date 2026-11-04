// @vitest-environment node
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { build } from "vite";
import { beforeAll, expect, test } from "vitest";

const CONSOLE = fileURLToPath(new URL("..", import.meta.url));
const BASE = "/console/";
const KB = 1000;
const PAGES = ["index.html", "explorer.html", "command.html", "holder.html"];

/** Budgets in bytes: JS and CSS gzip level 9 per page; fonts, wasm and world plates raw. */
const BUDGET = {
  pageJs: 40 * KB,
  pageCss: 10 * KB,
  seal: 90 * KB,
  wasm: 2_300 * KB,
  fonts: 120 * KB,
  world: 1_500 * KB,
} as const;

const gz = (path: string): number => gzipSync(readFileSync(path), { level: 9 }).length;

/** dist-relative paths a page fetches before any script runs: entry scripts, module preloads, stylesheets, preloaded fonts. */
function initialAssets(html: string): { js: string[]; css: string[]; fonts: string[] } {
  const hrefs = (re: RegExp): string[] => [...html.matchAll(re)].map((m) => m[1]!.slice(BASE.length));
  return {
    js: [...hrefs(/<script type="module" crossorigin src="([^"]+)"/g), ...hrefs(/<link rel="modulepreload" crossorigin href="([^"]+)"/g)],
    css: hrefs(/<link rel="stylesheet" crossorigin href="([^"]+)"/g),
    fonts: hrefs(/<link rel="preload" as="font" type="font\/woff2" crossorigin="" href="([^"]+)"/g),
  };
}

let dist = "";

beforeAll(async () => {
  dist = mkdtempSync(join(tmpdir(), "console-budget-"));
  await build({ root: CONSOLE, configFile: join(CONSOLE, "vite.config.ts"), logLevel: "silent", build: { outDir: dist, emptyOutDir: true } });
}, 30_000);

test("counts what a page loads up front and leaves lazy chunks out", () => {
  const html = [
    '<script type="module" crossorigin src="/console/assets/index-a1.js"></script>',
    '<link rel="modulepreload" crossorigin href="/console/assets/parse-b2.js">',
    '<link rel="stylesheet" crossorigin href="/console/assets/index-c3.css">',
    '<link rel="preload" as="font" type="font/woff2" crossorigin="" href="/console/assets/inter-latin-400-normal-d4.woff2">',
  ].join("\n");
  expect(initialAssets(html)).toEqual({
    js: ["assets/index-a1.js", "assets/parse-b2.js"],
    css: ["assets/index-c3.css"],
    fonts: ["assets/inter-latin-400-normal-d4.woff2"],
  });
});

test("an incompressible 60 KB script is over the page budget", () => {
  const dir = mkdtempSync(join(tmpdir(), "budget-"));
  mkdirSync(join(dir, "assets"));
  writeFileSync(join(dir, "assets", "index-a1.js"), randomBytes(60 * KB));
  expect(gz(join(dir, "assets", "index-a1.js"))).toBeGreaterThan(BUDGET.pageJs);
});

test.each(PAGES)("%s loads at most 40 KB of JS and 10 KB of CSS gzipped, and the five UI faces", (page) => {
  const assets = initialAssets(readFileSync(join(dist, page), "utf8"));
  const sum = (paths: readonly string[], size: (p: string) => number): number => paths.reduce((n, p) => n + size(join(dist, p)), 0);
  expect(assets.js.length).toBeGreaterThan(0);
  expect(sum(assets.js, gz)).toBeLessThanOrEqual(BUDGET.pageJs);
  expect(sum(assets.css, gz)).toBeLessThanOrEqual(BUDGET.pageCss);
  expect(assets.fonts).toHaveLength(5);
  expect(sum(assets.fonts, (p) => statSync(p).size)).toBeLessThanOrEqual(BUDGET.fonts);
});

test("the seal runtime stays lazy and within its weight", () => {
  const assets = readdirSync(join(dist, "assets"));
  const rive = assets.filter((f) => /^rive-.*\.js$/.test(f)).map((f) => gz(join(dist, "assets", f)));
  const wasm = assets.filter((f) => f.endsWith(".wasm"));
  expect(Math.max(...rive)).toBeLessThanOrEqual(BUDGET.seal);
  expect(wasm).toHaveLength(1);
  expect(statSync(join(dist, "assets", wasm[0]!)).size).toBeLessThanOrEqual(BUDGET.wasm);
  for (const page of PAGES) {
    expect(initialAssets(readFileSync(join(dist, page), "utf8")).js.filter((f) => f.includes("rive"))).toEqual([]);
  }
});

test("the world plates and frames weigh at most 1.5 MB together", () => {
  const world = join(dist, "world");
  const total = readdirSync(world).reduce((n, f) => n + statSync(join(world, f)).size, 0);
  expect(total).toBeLessThanOrEqual(BUDGET.world);
});
