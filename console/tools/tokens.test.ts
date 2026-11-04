import { expect, test } from "vitest";
import { headTags, manifest, readColors, readMotion, tokensCss, tokensModule } from "./tokens.ts";

const DESIGN = `---
name: Mandate
description: "Don't trust agents. Verify them."
colors:
  ink: "#0B0D10"
  bone: "#F6F4EE"
  verify: "#1FD598"
  alert: "#FF5C5C"
  muted: "#8A8F98"
  hairline: "rgb(246 244 238 / 0.14)"
typography:
  ledger:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "22px"
---

# Design System: Mandate
`;

const motion = (entries: readonly (readonly [string, string])[]): string =>
  JSON.stringify({ schemaVersion: 2, extensions: { motion: entries.map(([name, value]) => ({ name, value, purpose: "-" })) } });

const SEAL = [
  ["seam-snap", "133ms linear"],
  ["mismatch-open", "100ms linear"],
  ["mismatch-shake", "80ms steps(1, end)"],
  ["alert-enter", "120ms cubic-bezier(0.16, 1, 0.3, 1)"],
  ["bubble-enter", "120ms cubic-bezier(0.16, 1, 0.3, 1)"],
] as const;

test("reads the colour block of the DESIGN.md frontmatter and nothing else", () => {
  expect(readColors(DESIGN)).toEqual({
    ink: "#0B0D10",
    bone: "#F6F4EE",
    verify: "#1FD598",
    alert: "#FF5C5C",
    muted: "#8A8F98",
    hairline: "rgb(246 244 238 / 0.14)",
  });
});

test.each([
  ["verify", DESIGN.replace('  verify: "#1FD598"\n', ""), "tokens: DESIGN.md colors lack verify"],
  ["the frontmatter", DESIGN.replace(/^---\n/, ""), "tokens: DESIGN.md has no frontmatter"],
  ["the colour block", DESIGN.replace("colors:", "palette:"), "tokens: DESIGN.md has no colors"],
])("refuses a DESIGN.md without %s", (_, text, message) => {
  expect(() => readColors(text)).toThrow(message);
});

test("reads each motion token with its duration in milliseconds", () => {
  expect(readMotion(motion(SEAL)).map((m) => [m.name, m.ms])).toEqual([
    ["seam-snap", 133],
    ["mismatch-open", 100],
    ["mismatch-shake", 80],
    ["alert-enter", 120],
    ["bubble-enter", 120],
  ]);
});

test("refuses a motion token without a leading duration", () => {
  expect(() => readMotion(motion([["seam-snap", "fast"], ...SEAL.slice(1)]))).toThrow("tokens: motion seam-snap has no duration");
});

test("writes colours and motion as custom properties on :root", () => {
  const css = tokensCss({ colors: { ink: "#0B0D10", bone: "#F6F4EE" }, motion: [{ name: "alert-enter", value: "120ms ease", ms: 120 }] });
  expect(css).toBe(":root{--ink:#0B0D10;--bone:#F6F4EE;--motion-alert-enter:120ms ease;}\n");
});

test("exports colours and motion durations to canvas and timing code", () => {
  const js = tokensModule({ colors: { ink: "#0B0D10" }, motion: [{ name: "seam-snap", value: "133ms linear", ms: 133 }] });
  expect(js).toBe('export const COLORS = {"ink":"#0B0D10"};\nexport const MOTION_MS = {"seam-snap":133};\n');
});

test("the manifest starts and scopes the app at the console, in Ink", () => {
  expect(JSON.parse(manifest({ ink: "#0B0D10" }))).toEqual({
    name: "Mandate Console",
    short_name: "Mandate",
    start_url: "../",
    scope: "../",
    icons: [
      { src: "icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "icon-512.png", sizes: "512x512", type: "image/png" },
      { src: "maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
    theme_color: "#0B0D10",
    background_color: "#0B0D10",
    display: "standalone",
  });
});

test("every page head carries the icon set, manifest, theme colour and font preloads under the base", () => {
  const tags = headTags("/console/", "#0B0D10", ["assets/inter-latin-400-normal-a1.woff2"]);
  expect(tags.map((t) => [t.tag, t.attrs])).toEqual([
    ["link", { rel: "icon", href: "/console/brand/favicon.ico", sizes: "48x48" }],
    ["link", { rel: "icon", href: "/console/brand/favicon.svg", type: "image/svg+xml" }],
    ["link", { rel: "apple-touch-icon", href: "/console/brand/apple-touch-icon.png" }],
    ["link", { rel: "manifest", href: "/console/brand/site.webmanifest" }],
    ["meta", { name: "theme-color", content: "#0B0D10" }],
    ["link", { rel: "preload", as: "font", type: "font/woff2", crossorigin: "", href: "/console/assets/inter-latin-400-normal-a1.woff2" }],
  ]);
});

test("refuses a sidecar that drops one of the seal's motions", () => {
  expect(() => readMotion(motion(SEAL.slice(1)))).toThrow("tokens: design sidecar lacks motion seam-snap");
});
