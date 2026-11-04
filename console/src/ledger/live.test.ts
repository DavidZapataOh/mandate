import { beforeEach, describe, expect, it } from "vitest";
import { released } from "../scene/__fixtures__/cases";
import { LineStore } from "../store/store";
import { ATTACK, CONFIRM, patch } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { mountLedger } from "./ledger";
import { gameText } from "./narrate";

const deployCall = (verdict: string, reason: string, target: string) =>
  parseLine(
    patch(ATTACK, {
      source: "hook",
      forensic: null,
      event: { ...JSON.parse(CONFIRM).event, verdict, reason },
      subject: { agent: "release-1", tool: "bash", targets: [target], tool_use_id: "MANDATE_FIXTURE-2" },
    }),
  );

describe("live Muse Code lines", () => {
  let list: HTMLOListElement;
  let store: LineStore;

  beforeEach(() => {
    document.body.innerHTML = '<ol id="ledger"></ol>';
    list = document.getElementById("ledger") as HTMLOListElement;
    store = new LineStore();
    mountLedger(list, store, () => {});
  });

  it("names the exact command the hook allowed or refused", () => {
    expect(gameText(deployCall("MET", "ok: within scope", "cmd:nimbus deploy api-v2 prod-eu"))).toBe(
      "release-1 allowed bash cmd:nimbus deploy api-v2 prod-eu",
    );
    expect(
      gameText(deployCall("NOT_MET", "scope: target outside delegation", "cmd:nimbus migrate migration-0017 prod-eu")),
    ).toBe("release-1 denied bash cmd:nimbus migrate migration-0017 prod-eu: scope: target outside delegation");
  });

  it("badges hook rows LIVE and pinned Nimbus rows SCENARIO", () => {
    store.add(deployCall("MET", "ok: within scope", "cmd:nimbus deploy api-v2 prod-eu"));
    store.add(released());
    const badges = [...list.querySelectorAll<HTMLButtonElement>("button[data-seq]")].map((b) => [
      b.dataset.source,
      b.querySelector(".origin")?.textContent,
      b.getAttribute("aria-label")?.split(" · ")[0],
    ]);
    expect(badges).toEqual([
      ["deploy", "SCENARIO", "SCENARIO"],
      ["hook", "LIVE", "LIVE"],
    ]);
  });

  it("gives payment lines no provenance badge", () => {
    store.add(parseLine(CONFIRM));
    expect(list.querySelector(".origin")).toBeNull();
  });
});
