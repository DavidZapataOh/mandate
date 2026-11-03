import { closeForensic, forensicFetcher, openForensic } from "./forensic/drawer";
import { mountLedger } from "./ledger/ledger";
import type { Mode } from "./ledger/narrate";
import { LineStore } from "./store/store";
import { connectLive } from "./wire/client";
import { parseRecording, playRecording, replayName } from "./wire/replay";

const byId = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
};

const state = byId("stream-state");

function selectedReplay(): string | null | undefined {
  try {
    return replayName(location.search);
  } catch {
    return undefined;
  }
}

const name = selectedReplay();
const fetchLine = forensicFetcher(name !== null);
const store = new LineStore();
const aside = byId("forensic");
const ledger = mountLedger(byId("ledger"), store, (seq) => {
  void openForensic(aside, seq, store, fetchLine);
});

const buttons: Record<Mode, HTMLElement> = {
  game: byId("mode-game"),
  forensic: byId("mode-forensic"),
};
for (const [mode, el] of Object.entries(buttons) as [Mode, HTMLElement][]) {
  el.addEventListener("click", () => {
    ledger.setMode(mode);
    for (const [other, button] of Object.entries(buttons)) {
      button.setAttribute("aria-pressed", String(other === mode));
    }
  });
}

async function replay(name: string): Promise<void> {
  state.textContent = "REPLAY";
  try {
    const resp = await fetch(`./replay/${name}.jsonl`);
    if (!resp.ok) throw new Error(`replay: ${resp.status}`);
    playRecording(parseRecording(await resp.text()), (line) => void store.add(line));
  } catch {
    state.textContent = "REPLAY ERROR";
  }
}

function start(): void {
  if (name === undefined) {
    state.textContent = "REPLAY ERROR";
    return;
  }
  if (name !== null) {
    void replay(name);
    return;
  }
  connectLive({
    onLine: (line) => void store.add(line),
    onState: (next) => {
      state.textContent = next === "live" ? "LIVE" : "RECONNECTING";
    },
    onReset: () => {
      store.reset();
      closeForensic(aside);
    },
  });
}

start();
