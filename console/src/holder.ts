import "./shared/brand";
import "./intent/holder.css";
import { holderKey, indexedDbStore, pairHolder } from "./holder/keys";
import { httpIntentApi } from "./intent/api";
import { toBase64 } from "./intent/bytes";
import { IntentFlow } from "./intent/flow";
import { micRecorder } from "./intent/recorder";
import { bindIntent, renderIntent } from "./intent/widget";

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function register(publicKey: string, pairing: string): Promise<{ registered: boolean }> {
  const response = await fetch(`${location.origin}/api/holder`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ public_key: publicKey, pairing }),
  });
  if (!response.ok) throw new Error(`desk error ${response.status}`);
  return (await response.json()) as { registered: boolean };
}

async function boot(): Promise<void> {
  const keys = await holderKey(await indexedDbStore());
  const hash = location.hash;
  // The token is single-use; drop it from the address bar and history.
  if (hash) history.replaceState(null, "", location.pathname + location.search);
  const pairing = document.getElementById("pairing");
  try {
    const raw = await crypto.subtle.exportKey("raw", keys.publicKey);
    const note = await pairHolder(toBase64(raw), hash, register);
    if (note && pairing) pairing.textContent = note;
  } catch (error) {
    if (pairing) {
      pairing.textContent = `Pairing refused: ${message(error)}`;
      pairing.dataset.tone = "refused";
    }
  }
  const flow = new IntentFlow(httpIntentApi(location.origin, keys.privateKey), keys, (view) => renderIntent(document, view));
  const recorder = typeof MediaRecorder === "undefined" ? null : micRecorder();
  bindIntent(document, flow, recorder);
  renderIntent(document, flow.view);
}

boot().catch((error: unknown) => {
  const status = document.getElementById("intent-status");
  if (status) status.textContent = `Startup failed: ${message(error)}`;
});
