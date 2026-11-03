// @vitest-environment node
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import { describe, expect, it } from "vitest";
import { MARKER } from "./wire/__fixtures__/lines";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  });
}

/** Paths under dir whose bytes carry fixture data or a fixture module path. */
function fixtureLeaks(dir: string): string[] {
  return files(dir)
    .filter((path) => {
      const text = readFileSync(path, "latin1");
      return text.includes(MARKER) || text.includes("__fixtures__");
    })
    .map((path) => relative(dir, path));
}

describe("zero mock rows", () => {
  it("finds a planted fixture", () => {
    const dir = mkdtempSync(join(tmpdir(), "leak-"));
    mkdirSync(join(dir, "assets"));
    writeFileSync(join(dir, "assets", "index.js"), `const row = "${MARKER} row";`);
    writeFileSync(join(dir, "index.html"), "<!doctype html>");
    expect(fixtureLeaks(dir)).toEqual(["assets/index.js"]);
  });

  it("ships no fixture in the production build", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "console-dist-"));
    await build({
      root: ROOT,
      configFile: join(ROOT, "vite.config.ts"),
      logLevel: "silent",
      build: { outDir, emptyOutDir: true },
    });
    expect(files(outDir).map((p) => relative(outDir, p))).toContain("index.html");
    expect(fixtureLeaks(outDir)).toEqual([]);
  }, 30_000);
});
