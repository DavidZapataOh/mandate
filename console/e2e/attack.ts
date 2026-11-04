import { type APIRequestContext, expect, type Page } from "@playwright/test";

/** Fire a pinned template attack; returns the published line as JSON text. */
export async function attack(request: APIRequestContext, kind: string, base = ""): Promise<string> {
  const resp = await request.post(`${base}/api/attack`, { data: { kind } });
  expect(resp.status()).toBe(200);
  return resp.text();
}

export const row = (page: Page, seq: number) => page.locator(`#ledger button[data-seq="${seq}"]`);
