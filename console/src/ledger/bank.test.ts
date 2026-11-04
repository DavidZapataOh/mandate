import { beforeEach, describe, expect, it } from "vitest";
import { outcomeFor } from "../approval/state";
import { renderForensic } from "../forensic/drawer";
import { killSteps } from "../killcam/steps";
import { cueFor } from "../scene/cues";
import { LiveCues } from "../scene/live";
import { LineStore } from "../store/store";
import { BANK, CONFIRM, patch } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { mountLedger } from "./ledger";
import { cellsOf, forensicText, gameText } from "./narrate";
import { tally } from "./tally";

const bank = parseLine(BANK);

describe("bank lines in the ledger", () => {
  it("names what the bank reported and the object it reported on", () => {
    expect(gameText(bank)).toBe(
      "Bank reports: MANDATE_FIXTURE Account transfer created · sandbox_account_transfer_tts2u0bmjgmgyp08br4d",
    );
    expect(forensicText(bank)).toBe("#11 bank - - account_transfer.created");
    expect(cellsOf(bank)).toEqual({
      time: "08:58:56",
      actor: "bank",
      hash: "------",
      verdict: "NOTED",
      outcome: "note",
      struck: false,
    });
  });

  it("counts nothing and proves nothing", () => {
    const confirm = parseLine(CONFIRM);
    expect(tally([confirm, bank])).toEqual(tally([confirm]));
    expect(killSteps(bank)).toBeNull();
    expect(cueFor(bank)).toMatchObject({ outcome: "note", seal: null, route: "none", venue: "bank", bank: false });
    expect(outcomeFor([confirm, bank], "q:000001")).toEqual(outcomeFor([confirm], "q:000001"));
  });

  it("never animates", () => {
    const live = new LiveCues();
    const later = parseLine(patch(CONFIRM, { seq: 12 }));
    expect(live.take([bank]).map((l) => l.seq)).toEqual([]);
    expect(live.take([bank, later]).map((l) => l.seq)).toEqual([12]);
  });
});

describe("bank rows and drawer", () => {
  beforeEach(() => {
    document.body.innerHTML = '<ol id="ledger"></ol><aside id="drawer" hidden></aside>';
  });

  it("a bank row carries the SANDBOX badge and the bank's time", () => {
    const list = document.getElementById("ledger") as HTMLOListElement;
    const store = new LineStore();
    mountLedger(list, store, () => {});
    store.add(bank);
    const row = list.querySelector<HTMLButtonElement>('button[data-seq="11"]')!;
    expect([row.dataset.source, row.dataset.rail, row.dataset.outcome, row.querySelector(".rail")?.textContent]).toEqual([
      "bank",
      "sandbox",
      "note",
      "SANDBOX",
    ]);
    expect(row.getAttribute("aria-label")).toBe(
      "08:58:56 · bank · Bank reports: MANDATE_FIXTURE Account transfer created · sandbox_account_transfer_tts2u0bmjgmgyp08br4d · SANDBOX · (hash) ------ · NOTED",
    );
  });

  it("the drawer says Mandate decided nothing and shows the bank's ids", () => {
    const aside = document.getElementById("drawer") as HTMLElement;
    renderForensic(aside, bank);
    expect(aside.querySelector("h2")?.textContent).toBe("Line #11 · bank");
    expect([...aside.querySelectorAll("h3")].map((h) => h.textContent)).toEqual([
      "Decision",
      "Canonical action (CAVA)",
      "Attribution",
      "Subject",
    ]);
    const pres = [...aside.querySelectorAll("pre")].map((p) => p.textContent);
    expect(pres[0]).toBe("Reported by the bank; Mandate decided nothing here");
    expect(pres[3]).toContain('"event_id": "sandbox_event_001kmnw80hstceme2a6nzxcxzw7"');
  });
});
