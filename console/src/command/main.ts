import "../shared/brand";
import "./command.css";
import { closeForensic, forensicFetcher } from "../forensic/drawer";
import { LineStore } from "../store/store";
import { connectLive } from "../wire/client";
import { parseRecording, playRecording, replayName } from "../wire/replay";
import { parseProvenance, type ServerProvenance } from "./provenance";
import { mountCommand } from "./view";

const byId = (id: string): HTMLElement => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
};

const state = byId("stream-state");

function selectedReplay(): string | null | undefined {
  try {
    return replayName(location.search);
  } catch {
    return undefined;
  }
}

async function loadProvenance(): Promise<ServerProvenance | null> {
  try {
    const resp = await fetch("/api/provenance", { cache: "no-store" });
    return resp.ok ? parseProvenance(await resp.text()) : null;
  } catch {
    return null;
  }
}

function download(name: string, mime: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.hidden = true;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

async function replay(name: string, store: LineStore): Promise<void> {
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
  const name = selectedReplay();
  if (name === undefined) {
    state.textContent = "REPLAY ERROR";
    return;
  }
  const store = new LineStore();
  mountCommand(document, store, {
    replay: name,
    fetchLine: forensicFetcher(name !== null),
    loadProvenance: name === null ? loadProvenance : async () => null,
    now: Date.now,
    later: (run, ms) => void setTimeout(run, ms),
    download,
    schedule: (run) => void requestAnimationFrame(() => run()),
  });
  if (name !== null) {
    void replay(name, store);
    return;
  }
  const aside = byId("forensic");
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
