import { beforeEach, describe, expect, it } from "vitest";
import { LineStore } from "../store/store";
import type { DeskApi, DeviceState, PendingQuote } from "./api";
import { checked, desk, FIELDS, FIELDS_HASH, SUMMARY } from "./__fixtures__/desk";
import { DEVICE_POLL_MS, KNOWN_MAX, mountApproval } from "./panel";

const PAIRED: DeviceState = { paired: true, fingerprint: "630dcd2966c43366" };
const BEFORE_EXPIRY = 1800001000 * 1000;
const HOSTILE = "<img/src=x/onerror=window.pwned=1>";

class FakeDesk implements DeskApi {
  quotes: PendingQuote[] = [];
  state: DeviceState = PAIRED;
  pendingCalls = 0;
  deviceCalls = 0;
  down = false;
  async pending(): Promise<PendingQuote[]> {
    this.pendingCalls++;
    if (this.down) throw new Error("connection refused");
    return this.quotes.map((q) => ({ ...q }));
  }
  async device(): Promise<DeviceState> {
    this.deviceCalls++;
    return { ...this.state };
  }
}

let root: HTMLElement;
let store: LineStore;
let api: FakeDesk;
let scheduled: Array<() => void>;

function mount(
  nowMs = BEFORE_EXPIRY,
  subtle?: SubtleCrypto | null,
  deskApi: DeskApi | null = api,
) {
  return mountApproval(root, store, deskApi, {
    now: () => nowMs,
    schedule: (run, ms) => {
      expect(ms).toBe(DEVICE_POLL_MS);
      scheduled.push(run);
    },
    ...(subtle === undefined ? {} : { subtle }),
  });
}

const text = (selector: string) => root.querySelector(selector)?.textContent;
const steps = () =>
  [...root.querySelectorAll(".steps li")].map((li) => (li as HTMLElement).dataset.state);

beforeEach(() => {
  document.body.innerHTML = '<section id="approval" aria-label="Holder approval"></section>';
  root = document.getElementById("approval") as HTMLElement;
  store = new LineStore();
  api = new FakeDesk();
  api.quotes = [{ quote_id: "q:000001", consent: FIELDS }];
  scheduled = [];
});

describe("mountApproval", () => {
  it("stays hidden until a quote exists", async () => {
    api.quotes = [];
    await mount().refresh();
    expect(root.hidden).toBe(true);
  });

  it("shows the exact consent fields and their hash, never the summary", async () => {
    store.add(desk(1, "quote", "quoted"));
    await mount().refresh();
    expect(root.hidden).toBe(false);
    expect(root.dataset.phase).toBe("waiting");
    expect(text(".status")).toBe("Waiting for the holder");
    expect(text(".amount")).toBe("200.00 USD");
    expect(text(".payee")).toBe("to acme-991");
    expect([...root.querySelectorAll(".fields dt")].map((n) => n.textContent)).toEqual([
      "amount_cents", "currency", "expires_at", "nonce", "recipient", "reference", "source",
    ]);
    expect([...root.querySelectorAll(".fields dd")].map((n) => n.textContent)).toEqual([
      "20000", "USD", "1800001600", "00000000000000000000000000000001",
      "acme-991", "A-991", "checking-881",
    ]);
    expect(text(".hash")).toBe(FIELDS_HASH);
    expect(text(".expires")).toBe("Expires 2027-01-15 08:26:40 UTC");
    expect(text(".where")).toBe("Approve on the holder's device. This console holds no key.");
    expect(steps()).toEqual(["done", "current", "todo", "todo"]);
    expect(root.textContent).not.toContain("friend-001");
    expect(SUMMARY).toContain("friend-001");
  });

  it("offers no control that could approve", async () => {
    store.add(desk(1, "quote", "quoted"));
    await mount().refresh();
    expect(root.querySelectorAll("button, input, form, a").length).toBe(0);
  });

  it("renders a hostile payee as text", async () => {
    api.quotes = [{ quote_id: "q:000001", consent: { ...FIELDS, recipient: HOSTILE } }];
    store.add(desk(1, "quote", "quoted"));
    await mount().refresh();
    expect(text(".payee")).toBe(`to ${HOSTILE}`);
    expect(root.querySelector("img")).toBeNull();
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  });

  it("names the paired holder device", async () => {
    store.add(desk(1, "quote", "quoted"));
    await mount().refresh();
    expect(text(".device")).toBe("Holder device 630dcd2966c43366");
    expect(scheduled).toHaveLength(0);
  });

  it("polls the device state until a holder pairs, then stops", async () => {
    api.state = { paired: false, fingerprint: null };
    store.add(desk(1, "quote", "quoted"));
    await mount().refresh();
    expect(text(".device")).toBe("No holder device paired yet");
    expect(scheduled).toHaveLength(1);
    api.state = PAIRED;
    scheduled.shift()?.();
    await expect.poll(() => text(".device")).toBe("Holder device 630dcd2966c43366");
    expect(scheduled).toHaveLength(0);
    expect(api.deviceCalls).toBe(2);
  });

  it("surfaces a refused signature and keeps the quote open", async () => {
    store.add(desk(1, "quote", "quoted"));
    store.add(desk(2, "approve", "denied", { reason: "consent: bad signature" }));
    await mount().refresh();
    expect(root.dataset.phase).toBe("refused");
    expect(text(".status")).toBe("Approval refused");
    expect(text(".gate .reason")).toBe(
      "consent: bad signature. Nothing moved; the quote is still open.",
    );
    expect((root.querySelector(".gate") as HTMLElement).hidden).toBe(false);
    expect(steps()).toEqual(["done", "failed", "todo", "todo"]);
  });

  it("keeps the approved quote's fields after it leaves the pending list", async () => {
    store.add(desk(1, "quote", "quoted"));
    const mounted = mount();
    await mounted.refresh();
    api.quotes = [];
    store.add(desk(2, "approve", "approved"));
    await mounted.refresh();
    expect(root.dataset.phase).toBe("approved");
    expect(text(".status")).toBe(
      "Signed on the holder's device. Waiting for the agent to confirm.",
    );
    expect(text(".hash")).toBe(FIELDS_HASH);
    expect(steps()).toEqual(["done", "done", "current", "todo"]);
  });

  it("shows the paid outcome and that the gate checked the same consent", async () => {
    store.add(desk(1, "quote", "quoted"));
    const mounted = mount();
    await mounted.refresh();
    api.quotes = [];
    store.add(desk(2, "approve", "approved"));
    const paid = { payment_id: "pay:000001", reason: "ok: executed" };
    store.add(desk(3, "confirm", "confirmed", paid));
    await mounted.refresh();
    expect(root.dataset.phase).toBe("paid");
    expect(text(".status")).toBe("Verified at the gate · paid pay:000001");
    expect(root.dataset.gate).toBe("match");
    expect(text(".gate")).toBe("Gate checked the same consent hash");
    expect(steps()).toEqual(["done", "done", "done", "done"]);
  });

  it("folds to a one-line verdict once paid and expands on demand", async () => {
    store.add(desk(1, "quote", "quoted"));
    const mounted = mount();
    await mounted.refresh();
    expect(root.dataset.collapsed).toBeUndefined();
    api.quotes = [];
    store.add(desk(2, "approve", "approved"));
    store.add(desk(3, "confirm", "confirmed", { payment_id: "pay:000001" }));
    await mounted.refresh();
    const toggle = root.querySelector<HTMLElement>(".title");
    expect(root.dataset.collapsed).toBe("true");
    expect(toggle?.getAttribute("aria-expanded")).toBe("false");
    expect(text(".status")).toBe("Verified at the gate · paid pay:000001");
    toggle?.click();
    expect(root.dataset.collapsed).toBeUndefined();
    expect(toggle?.getAttribute("aria-expanded")).toBe("true");
    toggle?.click();
    expect(root.dataset.collapsed).toBe("true");
  });

  it("flags a gate check over different consent fields", async () => {
    store.add(desk(1, "quote", "quoted"));
    const mounted = mount();
    await mounted.refresh();
    const evil = { ...FIELDS, recipient: "evil-666" };
    store.add(desk(3, "confirm", "confirmed", { payment_id: "pay:000001" }, checked(evil)));
    await mounted.refresh();
    expect(root.dataset.gate).toBe("mismatch");
    expect(text(".gate")).toBe(
      "Gate checked a different consent hash: " +
        "f26b1efa 545f4c80 2f02d2fe fb03a83f 81b1de03 0233b9d5 8e60e692 88bceddd",
    );
    // The gate's digest is its own element, set like the shown one so the groups line up.
    expect(text(".gate .digest")).toBe(
      "f26b1efa 545f4c80 2f02d2fe fb03a83f 81b1de03 0233b9d5 8e60e692 88bceddd",
    );
  });

  it("shows the fields the gate checked when this console never saw the quote", async () => {
    api.quotes = [];
    store.add(desk(3, "confirm", "confirmed", { payment_id: "pay:000001" }));
    await mount().refresh();
    expect(text(".amount")).toBe("200.00 USD");
    expect(root.dataset.gate).toBe("checked");
    expect(text(".gate")).toBe(`Gate checked consent hash: ${FIELDS_HASH}`);
  });

  it("surfaces a denial at the gate with its reason", async () => {
    store.add(desk(1, "quote", "quoted"));
    store.add(desk(2, "approve", "approved"));
    store.add(desk(3, "confirm", "denied", { reason: "consent: expired" }));
    await mount().refresh();
    expect(root.dataset.phase).toBe("denied");
    expect(text(".status")).toBe("Denied at the gate");
    expect(text(".gate .reason")).toBe("consent: expired");
    expect(steps()).toEqual(["done", "done", "failed", "todo"]);
  });

  it.each([
    [1800001600 * 1000, "waiting"],
    [1800001601 * 1000, "expired"],
  ])("at %i ms an unapproved quote is %s", async (nowMs, phase) => {
    store.add(desk(1, "quote", "quoted"));
    await mount(nowMs).refresh();
    expect(root.dataset.phase).toBe(phase);
    if (phase === "expired") {
      expect(text(".status")).toBe("Expired");
      expect(text(".gate .reason")).toBe(
        "Expired at 2027-01-15 08:26:40 UTC. Approving now is refused.",
      );
    }
  });

  it("says why there is no hash without WebCrypto", async () => {
    store.add(desk(1, "quote", "quoted"));
    await mount(BEFORE_EXPIRY, null).refresh();
    expect(text(".hash")).toBe("Needs a secure origin (https or localhost)");
  });

  it("makes no mismatch claim when it cannot hash", async () => {
    store.add(desk(1, "quote", "quoted"));
    const mounted = mount(BEFORE_EXPIRY, null);
    await mounted.refresh();
    const evil = { ...FIELDS, recipient: "evil-666" };
    store.add(desk(3, "confirm", "confirmed", { payment_id: "pay:000001" }, checked(evil)));
    await mounted.refresh();
    expect(root.dataset.gate).toBe("checked");
    expect(text(".gate")).toBe(
      "Consent hash unavailable here: needs a secure origin (https or localhost)",
    );
  });

  it("re-reads the pending list when a desk line arrives and follows the new quote", async () => {
    store.add(desk(1, "quote", "quoted"));
    const mounted = mount();
    await mounted.refresh();
    const calls = api.pendingCalls;
    api.quotes.push({ quote_id: "q:000002", consent: { ...FIELDS, reference: "A-992" } });
    store.add(desk(2, "quote", "quoted", { quote_id: "q:000002" }));
    await expect.poll(() => root.dataset.quote).toBe("q:000002");
    expect(api.pendingCalls).toBe(calls + 1);
    expect([...root.querySelectorAll(".fields dd")][5]?.textContent).toBe("A-992");
  });

  it("keeps the last known state when the desk is unreachable", async () => {
    store.add(desk(1, "quote", "quoted"));
    const mounted = mount();
    await mounted.refresh();
    api.down = true;
    await mounted.refresh();
    expect((root.querySelector(".desk-error") as HTMLElement).hidden).toBe(false);
    expect(text(".amount")).toBe("200.00 USD");
  });

  it(`remembers at most ${KNOWN_MAX} quotes' fields`, async () => {
    api.quotes = Array.from({ length: KNOWN_MAX + 1 }, (_, i) => ({
      quote_id: `q:${String(i + 1).padStart(6, "0")}`,
      consent: FIELDS,
    }));
    store.add(desk(1, "quote", "quoted"));
    const mounted = mount();
    await mounted.refresh();
    api.quotes = [];
    await mounted.refresh();
    expect(text(".payee")).toBe("Consent fields not seen by this console");
  });

  it("in replay reads no desk and shows only what the lines carry", async () => {
    store.add(desk(1, "quote", "quoted"));
    store.add(desk(3, "confirm", "confirmed", { payment_id: "pay:000001" }));
    await mount(BEFORE_EXPIRY, undefined, null).refresh();
    expect([api.pendingCalls, api.deviceCalls]).toEqual([0, 0]);
    expect(text(".device")).toBe("Holder device not shown in replay");
    expect(text(".hash")).toBe(FIELDS_HASH);
    expect(scheduled).toHaveLength(0);
  });

  it("hides again when the store resets", async () => {
    store.add(desk(1, "quote", "quoted"));
    const mounted = mount();
    await mounted.refresh();
    api.quotes = [];
    store.reset();
    await mounted.refresh();
    expect(root.hidden).toBe(true);
  });
});
