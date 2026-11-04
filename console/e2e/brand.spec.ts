import { expect, test } from "@playwright/test";
import { CONSOLE_PAGES, type TextRun, textRuns, visit } from "./surfaces";

const WEIGHTS: Readonly<Record<string, readonly string[]>> = {
  Inter: ["400", "700", "800"],
  "JetBrains Mono": ["400", "700"],
  "Press Start 2P": ["400"],
};

/** Text set in a face or weight the brand does not ship, or in a face that never loaded. */
const offBrand = (runs: readonly TextRun[]): TextRun[] =>
  runs.filter((r) => !r.loaded || !(WEIGHTS[r.family] ?? []).includes(r.weight));

for (const surface of CONSOLE_PAGES) {
  test(`${surface.name} sets Bone on Ink in loaded brand faces`, async ({ page }) => {
    await visit(page, surface);
    const ground = await page.locator("body").evaluate((b) => [getComputedStyle(b).backgroundColor, getComputedStyle(b).color]);
    expect(ground).toEqual(["rgb(11, 13, 16)", "rgb(246, 244, 238)"]);
    expect(offBrand(await textRuns(page))).toEqual([]);
  });

  test(`${surface.name} themes the browser's own surfaces from the palette`, async ({ page }) => {
    await visit(page, surface);
    const surfaces = await page.evaluate(() => {
      const selection = getComputedStyle(document.body, "::selection");
      return {
        scrollbar: getComputedStyle(document.documentElement).scrollbarColor,
        selection: [selection.backgroundColor, selection.color],
        caret: getComputedStyle(document.body).caretColor,
        accent: getComputedStyle(document.body).accentColor,
      };
    });
    expect(surfaces).toEqual({
      scrollbar: "rgb(138, 143, 152) rgb(11, 13, 16)",
      selection: ["rgb(246, 244, 238)", "rgb(11, 13, 16)"],
      caret: "rgb(246, 244, 238)",
      accent: "rgb(246, 244, 238)",
    });
  });
}
