import { beforeEach, describe, expect, it, vi } from "vitest";
import { LineStore } from "../store/store";
import { ATTACK, CONFIRM, HOSTILE, SANDBOX_CONFIRM } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { closeForensic, forensicFetcher, openForensic, renderForensic } from "./drawer";

let aside: HTMLElement;

beforeEach(() => {
  document.body.innerHTML = '<aside id="forensic" hidden></aside>';
  aside = document.getElementById("forensic")!;
});

const titles = () => [...aside.querySelectorAll("h3")].map((h) => h.textContent);
const block = (title: string) =>
  [...aside.querySelectorAll("section")].find((s) => s.querySelector("h3")!.textContent === title)!
    .querySelector("pre")!.textContent!;

describe("renderForensic", () => {
  it("shows every piece of evidence of a paid line", () => {
    renderForensic(aside, parseLine(CONFIRM));
    expect(aside.hidden).toBe(false);
    expect(aside.querySelector("h2")!.textContent).toBe("Line #3 · desk");
    expect(titles()).toEqual([
      "Decision",
      "Canonical action (CAVA)",
      "Action hash",
      "Policy",
      "Certificate claims",
      "Holder consent",
      "Registry proof",
      "Anchor",
      "Bank transfer",
      "Attribution",
      "Subject",
    ]);
    expect(block("Action hash")).toBe(
      "52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b",
    );
    expect(JSON.parse(block("Certificate claims")).revocation_index).toBe(1);
    expect(JSON.parse(block("Holder consent")).nonce).toBe("00000000000000000000000000000001");
    expect(JSON.parse(block("Registry proof")).root).toBe(
      "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87",
    );
    expect(JSON.parse(block("Canonical action (CAVA)")).targets).toEqual([
      "amount:USD:20000",
      "from:checking-881",
      "ref:A-991",
      "to:acme-991",
    ]);
    expect(block("Anchor")).toBe("No anchor");
  });

  it("says what a denied line never got", () => {
    renderForensic(aside, parseLine(ATTACK));
    expect(block("Certificate claims")).toBe("No certificate issued");
    expect(block("Holder consent")).toBe("No consent presented");
    expect(block("Registry proof")).toBe("Not in the registry");
    expect(block("Attribution")).toBe("No model call");
    expect(block("Bank transfer")).toBe("No money moved");
  });

  it("names the layer when nothing reached the gate, as text", () => {
    renderForensic(aside, parseLine(HOSTILE));
    expect(titles()).toEqual(["Decision", "Canonical action (CAVA)", "Attribution", "Subject"]);
    expect(block("Decision")).toBe("Decided by mcp: denied: server undeclared");
    expect(block("Canonical action (CAVA)")).toBe("Nothing reached the gate");
    expect(block("Subject")).toContain('<img src=x onerror=\\"window.pwned=1\\">');
    expect(aside.querySelector("img")).toBeNull();
  });

  it("closes", () => {
    renderForensic(aside, parseLine(ATTACK));
    [...aside.querySelectorAll("button")].find((b) => b.textContent === "Close")!.click();
    expect(aside.hidden).toBe(true);
  });
});

describe("openForensic", () => {
  it("asks the server for a line the store let go", async () => {
    const asked: number[] = [];
    const fetchLine = async (seq: number) => {
      asked.push(seq);
      return seq === 4 ? parseLine(ATTACK) : null;
    };
    const store = new LineStore();
    store.add(parseLine(CONFIRM));
    expect(await openForensic(aside, 3, store, fetchLine)).toBe(true);
    expect(asked).toEqual([]);
    expect(await openForensic(aside, 4, store, fetchLine)).toBe(true);
    expect(aside.querySelector("h2")!.textContent).toBe("Line #4 · attack");
    aside.hidden = true;
    expect(await openForensic(aside, 9, store, fetchLine)).toBe(false);
    expect(asked).toEqual([4, 9]);
    expect(aside.hidden).toBe(true);
  });
});

describe("forensicFetcher", () => {
  it("asks the live server for a line", async () => {
    const fetchImpl = vi.fn(async () => new Response(ATTACK, { status: 200 }));
    expect((await forensicFetcher(false, fetchImpl)(4))?.seq).toBe(4);
    expect(fetchImpl).toHaveBeenCalledWith("/api/forensic/4");
  });

  it("never asks the live server while replaying", async () => {
    const fetchImpl = vi.fn(async () => new Response(ATTACK, { status: 200 }));
    expect(await forensicFetcher(true, fetchImpl)(4)).toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe("closeForensic", () => {
  it("hides the drawer and drops the line it showed", () => {
    renderForensic(aside, parseLine(ATTACK));
    closeForensic(aside);
    expect(aside.hidden).toBe(true);
    expect(aside.childElementCount).toBe(0);
  });

  it("names the rail and the bank's own transfer id", () => {
    renderForensic(aside, parseLine(SANDBOX_CONFIRM));
    expect(JSON.parse(block("Bank transfer"))).toEqual({
      rail: "sandbox",
      provider: "increase",
      transfer_id: "sandbox_account_transfer_MANDATE_FIXTURE",
      status: "complete",
      idempotency_key: "mandate-cert-00000000000000000000000000000002",
    });
  });
});
