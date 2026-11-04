// @vitest-environment node
import { readFileSync } from "node:fs";
import { expect, test } from "vitest";

test("an empty result stays in the accessibility tree so its first announcement is read", () => {
  const css = readFileSync(new URL("../console.css", import.meta.url), "utf8");
  const rule = /#attacks \.result:empty\s*\{([^}]*)\}/.exec(css);
  expect(rule?.[1]).not.toMatch(/display\s*:\s*none/);
});
