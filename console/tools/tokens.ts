import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Plugin } from "vite";

export interface Motion {
  readonly name: string;
  readonly value: string;
  readonly ms: number;
}

export interface DesignTokens {
  readonly colors: Readonly<Record<string, string>>;
  readonly motion: readonly Motion[];
}

export const BRAND_COLORS = ["ink", "bone", "verify", "alert", "muted"] as const;

const CSS_ID = "virtual:brand.css";
const JS_ID = "virtual:brand";

/** The `key: "value"` lines of DESIGN.md's frontmatter `colors:` block, in order. */
export function readColors(markdown: string): Record<string, string> {
  if (!markdown.startsWith("---\n")) throw new Error("tokens: DESIGN.md has no frontmatter");
  const end = markdown.indexOf("\n---\n", 3);
  if (end === -1) throw new Error("tokens: DESIGN.md has no frontmatter");
  const lines = markdown.slice(4, end).split("\n");
  const start = lines.indexOf("colors:");
  if (start === -1) throw new Error("tokens: DESIGN.md has no colors");
  const colors: Record<string, string> = {};
  for (const line of lines.slice(start + 1)) {
    if (!/^\s/.test(line)) break;
    const m = /^\s+([\w-]+):\s*"([^"]*)"\s*$/.exec(line);
    if (m) colors[m[1]!] = m[2]!;
  }
  const missing = BRAND_COLORS.find((slug) => !(slug in colors));
  if (missing !== undefined) throw new Error(`tokens: DESIGN.md colors lack ${missing}`);
  return colors;
}

/** The design sidecar's `extensions.motion` entries with their leading duration in milliseconds. */
export function readMotion(sidecar: string): Motion[] {
  const parsed = JSON.parse(sidecar) as { extensions?: { motion?: readonly { name: string; value: string }[] } };
  return (parsed.extensions?.motion ?? []).map(({ name, value }) => {
    const m = /^(\d+)ms\b/.exec(value);
    if (!m) throw new Error(`tokens: motion ${name} has no duration`);
    return { name, value, ms: Number(m[1]) };
  });
}

/** The tokens as custom properties on `:root`: colours first, then `--motion-<name>`. */
export function tokensCss(t: DesignTokens): string {
  const colors = Object.entries(t.colors).map(([slug, value]) => `--${slug}:${value};`);
  const motion = t.motion.map((m) => `--motion-${m.name}:${m.value};`);
  return `:root{${[...colors, ...motion].join("")}}\n`;
}

/** The tokens as an ES module for canvas and timing code. */
export function tokensModule(t: DesignTokens): string {
  const ms = Object.fromEntries(t.motion.map((m) => [m.name, m.ms]));
  return `export const COLORS = ${JSON.stringify(t.colors)};\nexport const MOTION_MS = ${JSON.stringify(ms)};\n`;
}

/** Vite plugin serving DESIGN.md and its sidecar as `virtual:brand.css` and `virtual:brand`. */
export function brandTokens(root: string): Plugin {
  const design = join(root, "DESIGN.md");
  const sidecar = join(root, ".impeccable", "design.json");
  return {
    name: "mandate-brand-tokens",
    resolveId(id) {
      return id === CSS_ID || id === JS_ID ? `\0${id}` : null;
    },
    load(id) {
      if (id !== `\0${CSS_ID}` && id !== `\0${JS_ID}`) return null;
      this.addWatchFile(design);
      this.addWatchFile(sidecar);
      const tokens: DesignTokens = {
        colors: readColors(readFileSync(design, "utf8")),
        motion: readMotion(readFileSync(sidecar, "utf8")),
      };
      return id === `\0${CSS_ID}` ? tokensCss(tokens) : tokensModule(tokens);
    },
  };
}
