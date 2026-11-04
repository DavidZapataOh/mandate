import { type APIRequestContext, expect, type Page } from "@playwright/test";

/** Fire a pinned template attack; returns the published line as JSON text. */
export async function attack(request: APIRequestContext, kind: string, base = ""): Promise<string> {
  const resp = await request.post(`${base}/api/attack`, { data: { kind } });
  expect(resp.status()).toBe(200);
  return resp.text();
}

/** Run one pinned Nimbus deploy step; returns the published line as JSON text. */
export async function deploy(request: APIRequestContext, step: string): Promise<string> {
  const resp = await request.post("/api/deploy", { data: { step } });
  expect(resp.status()).toBe(200);
  return resp.text();
}

export const row = (page: Page, seq: number) => page.locator(`#ledger button[data-seq="${seq}"]`);
