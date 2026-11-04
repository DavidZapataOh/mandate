import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ATTACK } from "../wire/__fixtures__/lines";
import { AUDITOR, forge, GATE_KEY, HOLDER_KEY, RECEIPT, tamper } from "./__fixtures__/receipts";
import OTS from "./__fixtures__/ots.json" with { type: "json" };
import { WITHHELD } from "./exposure";
import { mountExplorer, type Explorer } from "./view";

const PAGE = readFileSync("explorer.html", "utf8");
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** A server that publishes the fixture keys and stores the golden receipt (auditor copy by default). */
function server(routes: Record<string, Response> = {}) {
  const seen: string[] = [];
  const fetchFn = async (url: string) => {
    seen.push(url);
    const hit = {
      "/api/keys": json(200, { gate_key: GATE_KEY, holder_keys: [HOLDER_KEY] }),
      "/api/receipt/pay%3A000001": json(200, JSON.parse(AUDITOR)),
      "/api/receipt/pay%3A000001?disclose=all": json(200, JSON.parse(RECEIPT)),
      ...routes,
    }[url];
    return hit ?? json(404, { error: "not found" });
  };
  return { fetchFn, seen };
}
const offline = async () => {
  throw new TypeError("Failed to fetch");
};

let explorer: Explorer;
async function mount(fetchFn: (url: string) => Promise<Response>) {
  explorer = mountExplorer(document, fetchFn);
  await explorer.ready;
  return async (text: string) => {
    (document.getElementById("paste") as HTMLTextAreaElement).value = text;
    await explorer.verify();
  };
}
const verdict = () => document.querySelector("#verdict .label")?.textContent;
const verdictText = () => document.querySelector("#verdict .text")?.textContent;
const marks = () => [...document.querySelectorAll("#steps li")].map((li) => li.querySelector(".mark")?.textContent);
const revealed = () => [...document.querySelectorAll("#reveals dd")].map((d) => d.textContent);
const tick = (group: string) => {
  (document.querySelector(`#reveal input[value="${group}"]`) as HTMLInputElement).checked = true;
};

beforeEach(() => {
  document.documentElement.innerHTML = PAGE.replace(/^<!doctype html>/i, "");
});
afterEach(() => {
  vi.useRealTimers();
});

/** A server whose receipt answers wait until the test releases them, in any order. */
function held() {
  const waiting: { url: string; signal: AbortSignal | undefined; release: () => void }[] = [];
  const { fetchFn: answer } = server();
  const fetchFn = (url: string, init?: { signal?: AbortSignal }) => {
    if (url === "/api/keys") return answer(url);
    return new Promise<Response>((resolve) => {
      waiting.push({ url, signal: init?.signal, release: () => void answer(url).then(resolve) });
    });
  };
  return { fetchFn, waiting };
}
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("explorer page", () => {
  it("verifies a payment id against the published key without its personal fields", async () => {
    const { fetchFn, seen } = server();
    const verify = await mount(fetchFn);
    expect(document.getElementById("key-source")!.textContent).toBe("Published by this server");
    expect((document.getElementById("gate-key") as HTMLInputElement).value).toBe(GATE_KEY);
    await verify("pay:000001");
    expect(verdict()).toBe("VERIFIED, FIELDS WITHHELD");
    expect(document.getElementById("verdict")!.dataset.verdict).toBe("withheld");
    expect(marks()).toEqual(["PASS", "PASS", "PASS", "WITHHELD", "PASS", "WITHHELD", "PASS", "PASS", "NOT CHECKED", "PASS", "PASS", "PASS"]);
    expect(seen).toEqual(["/api/keys", "/api/receipt/pay%3A000001"]);
    expect([...document.querySelectorAll("#reveals dt")].map((d) => d.textContent)).toEqual([
      "Amount", "Payee account", "Debit account", "Reference", "Payment and quote ids", "Consent key (this payment only)",
      "Holder public key", "Sealed at (unix seconds)", "Bank transfer",
    ]);
    expect(revealed().slice(0, 2)).toEqual([WITHHELD, WITHHELD]);
    expect(document.querySelectorAll("#never li")).toHaveLength(6);
    expect(document.getElementById("anonymity")!.textContent).toBe("Anonymity set: 1 holder key. Every receipt this server issued was approved by that one holder.");
    expect(document.getElementById("limits")!.textContent).toBe(
      "Receipts share no holder key: each payment is signed by a key used once, and the holder's own key appears only when the holder discloses it. The gate that issued a receipt can still link it to its holder. A withheld field cannot be confirmed by guessing: the certificate's action hash is salted.",
    );
  });

  it("states the anonymity set the server publishes, and drops it for a pinned key", async () => {
    const { fetchFn } = server({ "/api/keys": json(200, { gate_key: GATE_KEY, holder_keys: [HOLDER_KEY, "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E="] }) });
    await mount(fetchFn);
    expect(document.getElementById("anonymity")!.textContent).toMatch(/^Anonymity set: 2 holder keys\./);
    const key = document.getElementById("gate-key") as HTMLInputElement;
    key.value = GATE_KEY;
    key.dispatchEvent(new Event("input"));
    expect(document.getElementById("anonymity")!.textContent).toBe("Anonymity set unknown: this page has no holder list from the server.");
  });

  it("says the anonymity set is unknown when no keys are published", async () => {
    await mount(offline);
    expect(document.getElementById("anonymity")!.textContent).toBe("Anonymity set unknown: this page has no holder list from the server.");
  });

  it("marks every withheld field of the reveals list, term and value", async () => {
    const verify = await mount(server().fetchFn);
    await verify(AUDITOR);
    const rows = [...document.querySelectorAll("#reveals dt")].map((dt) => [
      dt.textContent,
      dt.hasAttribute("data-withheld"),
      (dt.nextElementSibling as HTMLElement).hasAttribute("data-withheld"),
    ]);
    expect(rows).toEqual([
      ["Amount", true, true],
      ["Payee account", true, true],
      ["Debit account", true, true],
      ["Reference", true, true],
      ["Payment and quote ids", false, false],
      ["Consent key (this payment only)", false, false],
      ["Holder public key", true, true],
      ["Sealed at (unix seconds)", false, false],
      ["Bank transfer", false, false],
    ]);
    await verify(RECEIPT);
    expect(document.querySelectorAll("#reveals [data-withheld]")).toHaveLength(0);
  });

  it("loads the holder copy and verifies every link", async () => {
    const { fetchFn, seen } = server();
    const verify = await mount(fetchFn);
    await verify("pay:000001");
    await explorer.holderCopy();
    expect(verdict()).toBe("VERIFIED");
    expect(marks()).toEqual([...Array(8).fill("PASS"), "NOT CHECKED", ...Array(3).fill("PASS")]);
    expect(seen.at(-1)).toBe("/api/receipt/pay%3A000001?disclose=all");
    expect(revealed().slice(0, 2)).toEqual(["200.00 USD", "acme-991"]);
  });

  it("marks a pending public anchor PENDING and keeps the verdict", async () => {
    const verify = await mount(server().fetchFn);
    await verify(tamper("public_anchor", { v: 1, ots: OTS.golden.pending, bitcoin: null }));
    expect(marks()).toEqual([...Array(8).fill("PASS"), "PENDING", ...Array(3).fill("PASS")]);
    expect(document.querySelector('#steps li[data-step="Public anchor"]')?.getAttribute("data-status")).toBe("pending");
    expect(verdict()).toBe("VERIFIED");
  });

  it("makes an auditor copy that discloses only the ticked fields", async () => {
    const verify = await mount(server().fetchFn);
    await verify(RECEIPT);
    tick("amount");
    await explorer.present();
    const copy = JSON.parse((document.getElementById("presentation") as HTMLTextAreaElement).value);
    expect(copy.sd.split("~")).toHaveLength(4);
    expect(verdict()).toBe("VERIFIED, FIELDS WITHHELD");
    expect(revealed().slice(0, 4)).toEqual(["200.00 USD", WITHHELD, WITHHELD, WITHHELD]);
  });

  it("makes each auditor copy from the receipt verified, not from the last copy made", async () => {
    const verify = await mount(server().fetchFn);
    await verify(RECEIPT);
    tick("amount");
    await explorer.present();
    tick("payee");
    await explorer.present();
    const copy = JSON.parse((document.getElementById("presentation") as HTMLTextAreaElement).value);
    expect(copy.sd.split("~")).toHaveLength(5);
    expect(revealed().slice(0, 2)).toEqual(["200.00 USD", "acme-991"]);
  });

  it("never shows a pass after the failing step", async () => {
    const verify = await mount(server().fetchFn);
    await verify(forge("amount_cents", 2000000));
    expect(verdict()).toBe("NOT VERIFIED");
    expect(verdictText()).toBe("Failed at Receipt disclosures: Disclosures do not verify (sd-jwt: disclosure not referenced)");
    expect(marks()).toEqual(["PASS", "PASS", "FAIL", ...Array(9).fill("NOT CHECKED")]);
    expect(document.querySelector('#steps li[data-status="fail"]')?.getAttribute("data-step")).toBe("Receipt disclosures");
  });

  it("verifies a pasted receipt with a hand-pinned key and no server", async () => {
    const verify = await mount(offline);
    expect(document.getElementById("key-source")!.textContent).toBe(
      "No key published here: paste the gate public key",
    );
    const key = document.getElementById("gate-key") as HTMLInputElement;
    key.value = GATE_KEY;
    key.dispatchEvent(new Event("input"));
    expect(document.getElementById("key-source")!.textContent).toBe("Pinned by you");
    await verify(RECEIPT);
    expect(verdict()).toBe("VERIFIED");
  });

  it.each([
    ["pay:000001", offline, "The server is unreachable; paste the receipt itself to verify offline"],
    ["pay:000009", server().fetchFn, "No receipt for pay:000009 on this server"],
    [ATTACK, server().fetchFn, "Line #4 carries no payment receipt"],
    ["hello", server().fetchFn, "Paste a receipt, a certificate, a payment id or a console line"],
  ])("refuses %j with a reason and no steps", async (text, fetchFn, reason) => {
    const verify = await mount(fetchFn);
    const key = document.getElementById("gate-key") as HTMLInputElement;
    key.value = GATE_KEY;
    await verify(text);
    expect(verdict()).toBe("CANNOT VERIFY");
    expect(verdictText()).toBe(reason);
    expect(marks()).toEqual([]);
    expect(document.querySelectorAll("#reveals dt")).toHaveLength(0);
  });

  it("asks for a payment id before the holder copy and for a receipt before the auditor copy", async () => {
    await mount(server().fetchFn);
    await explorer.holderCopy();
    expect(verdictText()).toBe("Look a payment up by its id first; the holder copy comes from this desk");
    await explorer.present();
    expect(verdictText()).toBe("Verify a receipt first");
  });

  it("refuses a key that is not 32 bytes", async () => {
    const verify = await mount(offline);
    (document.getElementById("gate-key") as HTMLInputElement).value = "AAAA";
    await verify(RECEIPT);
    expect(verdictText()).toBe("The gate key must be 32 bytes of base64");
  });

  it("shows attacker text in a receipt as text", async () => {
    const verify = await mount(server().fetchFn);
    const hostile = "<img src=x onerror=window.pwned=1>";
    await verify(tamper("payment_id", hostile));
    expect(verdict()).toBe("NOT VERIFIED");
    expect(document.querySelector("#steps img")).toBeNull();
    expect(document.querySelector('#steps li[data-step="Receipt format"] p')?.textContent).toBe(`Receipt for ${hostile}`);
    expect(verdictText()).toBe(`Failed at Receipt disclosures: Disclosures are for pay:000001, not ${hostile}`);
  });

  it("says where the holder copy lives when this server refuses it", async () => {
    const { fetchFn } = server({
      "/api/receipt/pay%3A000001?disclose=all": json(403, { error: "holder copy is local only" }),
    });
    const verify = await mount(fetchFn);
    await verify("pay:000001");
    await explorer.holderCopy();
    expect(verdict()).toBe("CANNOT VERIFY");
    expect(verdictText()).toBe("The holder copy is served only on the desk's own machine; paste it here instead");
  });

  it("refuses a looked-up receipt for another payment than the one asked for", async () => {
    const { fetchFn } = server({ "/api/receipt/pay%3A000002": json(200, JSON.parse(AUDITOR)) });
    const verify = await mount(fetchFn);
    await verify("pay:000002");
    expect(verdict()).toBe("CANNOT VERIFY");
    expect(verdictText()).toBe("The server answered with the receipt for pay:000001, not pay:000002");
    expect(marks()).toEqual([]);
    expect(document.querySelectorAll("#reveals dt")).toHaveLength(0);
  });

  it("clears the last verdict while a lookup is pending", async () => {
    const { fetchFn, waiting } = held();
    const verify = await mount(fetchFn);
    await verify(RECEIPT);
    expect(verdict()).toBe("VERIFIED");
    (document.getElementById("paste") as HTMLTextAreaElement).value = "pay:000001";
    const pending = explorer.verify();
    await settle();
    expect(document.getElementById("verdict")!.textContent).toBe("");
    expect(document.getElementById("verdict")!.dataset.verdict).toBeUndefined();
    expect(marks()).toEqual([]);
    expect(document.querySelectorAll("#reveals dt")).toHaveLength(0);
    waiting[0]!.release();
    await pending;
    expect(verdict()).toBe("VERIFIED, FIELDS WITHHELD");
  });

  it("drops a lookup that a later verify superseded", async () => {
    const { fetchFn, waiting } = held();
    const verify = await mount(fetchFn);
    (document.getElementById("paste") as HTMLTextAreaElement).value = "pay:000001";
    const first = explorer.verify();
    await settle();
    await verify(RECEIPT);
    waiting[0]!.release();
    await first;
    expect(verdict()).toBe("VERIFIED");
    expect(marks()).toEqual([...Array(8).fill("PASS"), "NOT CHECKED", ...Array(3).fill("PASS")]);
    expect(revealed().slice(0, 2)).toEqual(["200.00 USD", "acme-991"]);
    expect(document.querySelectorAll("#reveals dt")).toHaveLength(9);
    // The superseded lookup leaves no payment id behind for the holder copy.
    await explorer.holderCopy();
    expect(verdictText()).toBe("Look a payment up by its id first; the holder copy comes from this desk");
  });

  it("gives up on a lookup after ten seconds and says the server is unreachable", async () => {
    const { fetchFn, waiting } = held();
    const verify = await mount(fetchFn);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    (document.getElementById("paste") as HTMLTextAreaElement).value = "pay:000001";
    const pending = explorer.verify();
    await vi.advanceTimersByTimeAsync(9_999);
    expect(document.getElementById("verdict")!.textContent).toBe("");
    await vi.advanceTimersByTimeAsync(1);
    await pending;
    expect(waiting[0]!.signal?.aborted).toBe(true);
    expect(verdict()).toBe("CANNOT VERIFY");
    expect(verdictText()).toBe("The server is unreachable; paste the receipt itself to verify offline");
    void verify;
  });
});
