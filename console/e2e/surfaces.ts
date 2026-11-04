import { expect, type Page } from "@playwright/test";

export interface Surface {
  readonly name: string;
  readonly path: string;
}

export const CONSOLE_PAGES: readonly Surface[] = [
  { name: "console", path: "/console/" },
  { name: "explorer", path: "/console/explorer.html" },
  { name: "command", path: "/console/command.html" },
  { name: "holder", path: "/console/holder.html" },
];
export const GLASSES: Surface = { name: "glasses", path: "/app/" };
export const SURFACES: readonly Surface[] = [...CONSOLE_PAGES, GLASSES];
export const ATTACKS = ["payee_swap", "amount_inflate", "replay", "post_cert_mutation", "scope_escalation", "mcp_exfil", "forged_approval"] as const;

/** Open a surface and wait until its main landmark shows and its fonts settle. */
export async function visit(page: Page, surface: Surface): Promise<void> {
  await page.goto(surface.path);
  await expect(page.locator("main")).toBeVisible();
  await page.evaluate(async () => {
    await document.fonts.ready;
  });
}

export interface TextRun {
  readonly where: string;
  readonly text: string;
  readonly family: string;
  readonly weight: string;
  readonly size: number;
  readonly loaded: boolean;
}

/** Every rendered text node's element, face, weight and size; hidden and 1px clip text excluded. */
export function textRuns(page: Page): Promise<TextRun[]> {
  return page.evaluate(() => {
    const runs: TextRun[] = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
      const text = node.textContent?.trim() ?? "";
      const el = node.parentElement;
      if (text === "" || el === null || el.closest("[hidden], [aria-hidden='true'], script, style") !== null) continue;
      const box = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      if (box.width <= 1 || box.height <= 1 || style.visibility !== "visible") continue;
      const family = style.fontFamily.split(",")[0]!.trim().replace(/^["']|["']$/g, "");
      runs.push({
        where: `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${el.classList.length ? `.${[...el.classList].join(".")}` : ""}`,
        text: text.slice(0, 40),
        family,
        weight: style.fontWeight,
        size: Number.parseFloat(style.fontSize),
        loaded: document.fonts.check(`${style.fontWeight} 16px "${family}"`),
      });
    }
    return runs;
  });
}
