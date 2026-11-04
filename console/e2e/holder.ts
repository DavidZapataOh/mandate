import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, type Browser, type Page } from "@playwright/test";

const BIN = process.env.MANDATE_CONSOLE ?? "../.venv/bin/mandate-console";
// The default is anchored here: a relative path would resolve against the agent's cwd.
const PYTHON =
  process.env.MANDATE_PYTHON ?? fileURLToPath(new URL("../../.venv/bin/python", import.meta.url));
const DIST = fileURLToPath(new URL("../dist", import.meta.url));
const REPO = fileURLToPath(new URL("../..", import.meta.url));

export interface Desk {
  base: string;
  pairUrl: string;
  stop(): Promise<void>;
}

/** A fresh `mandate-console` of its own, so each test pairs a new holder. */
export async function startDesk(port: number): Promise<Desk> {
  const proc: ChildProcess = spawn(BIN, ["--port", String(port), "--console-dir", DIST], {
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const pairUrl = await new Promise<string>((resolve, reject) => {
    let out = "";
    const timer = setTimeout(
      () => reject(new Error(`mandate-console did not start: ${out}`)),
      20_000,
    );
    proc.stdout?.on("data", (chunk: Buffer) => {
      out += chunk.toString();
      const pair = /^Pair the holder device: (\S+)$/m.exec(out);
      if (pair?.[1] && /^Console: /m.test(out)) {
        clearTimeout(timer);
        resolve(pair[1]);
      }
    });
    proc.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`mandate-console exited ${code}: ${out}`));
    });
  });
  const base = `http://127.0.0.1:${port}`;
  await expect
    .poll(async () => (await fetch(`${base}/api/device`).catch(() => null))?.status ?? 0, {
      timeout: 10_000,
    })
    .toBe(200);
  return {
    base,
    pairUrl,
    stop: () =>
      new Promise<void>((resolve) => {
        if (proc.exitCode !== null) return resolve();
        proc.once("exit", () => resolve());
        proc.kill("SIGINT");
      }),
  };
}

/** One desk tool call made the way an agent makes it: over MCP. */
export function agent(desk: Desk, ...args: string[]): Record<string, unknown> {
  const out = execFileSync(PYTHON, ["-m", "e2e.desk_agent", `${desk.base}/mcp`, ...args], {
    cwd: REPO,
  });
  return JSON.parse(out.toString()) as Record<string, unknown>;
}

/** The holder's own device: a separate browser profile on the WebMCP page. */
export async function pairHolder(browser: Browser, desk: Desk): Promise<Page> {
  const device = await (await browser.newContext()).newPage();
  await device.goto(desk.pairUrl);
  await expect(device.locator("#pairing")).toHaveText("Paired with the desk.");
  return device;
}
