import { type ChildProcess, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const BIN = process.env.MANDATE_CONSOLE ?? `${ROOT}.venv/bin/mandate-console`;
const PYTHON = `${ROOT}.venv/bin/python`;
const DIST = fileURLToPath(new URL("../dist", import.meta.url));

export interface OwnConsole {
  base: string;
  pairing: string;
  stop(): void;
}

/** Start a console server of our own, so the test can read its one-time pairing token. */
export async function startConsole(port: number): Promise<OwnConsole> {
  const child: ChildProcess = spawn(BIN, ["--port", String(port), "--console-dir", DIST], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  const base = `http://127.0.0.1:${port}`;
  const pairing = await new Promise<string>((resolve, reject) => {
    let out = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      out += chunk.toString();
      const m = /#pair=([\w-]+)/.exec(out);
      if (m?.[1]) resolve(m[1]);
    });
    child.on("exit", (code) => reject(new Error(`console exited ${code}`)));
  });
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${base}/console/`)).ok) break;
    } catch {
      // Not listening yet.
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return { base, pairing, stop: () => void child.kill() };
}

export interface PendingPayment {
  /** Confirm the approved quote now; resolves with the confirm status. */
  confirm(): Promise<string>;
}

/** Quote and approve one desk payment through MCP, holding the confirmation until asked. */
export async function approvedPayment(own: OwnConsole): Promise<PendingPayment> {
  const child = spawn(PYTHON, [`${ROOT}console/e2e/desk_payment.py`, own.base, own.pairing], {
    cwd: ROOT,
    env: { ...process.env, PYTHONPATH: ROOT },
    stdio: ["pipe", "pipe", "inherit"],
  });
  const lines: string[] = [];
  const waiters: (() => void)[] = [];
  let buffer = "";
  child.stdout?.on("data", (chunk: Buffer) => {
    buffer += chunk.toString();
    const parts = buffer.split("\n");
    buffer = parts.pop() ?? "";
    lines.push(...parts.filter(Boolean));
    for (const wake of waiters.splice(0)) wake();
  });
  const nextLine = async (): Promise<string> => {
    while (lines.length === 0) {
      if (child.exitCode !== null) throw new Error(`desk payment exited ${child.exitCode}`);
      await new Promise<void>((r) => {
        waiters.push(r);
        child.once("exit", () => r());
      });
    }
    return lines.shift() as string;
  };
  if ((await nextLine()) !== "approved") throw new Error("desk payment: not approved");
  return {
    async confirm() {
      child.stdin?.end("go\n");
      return nextLine();
    },
  };
}
