import { fromJwsSegment } from "./bytes";
import { sha256Hex } from "./canon";
import { EVENT_TYPE } from "./chain";
import type { Receipt } from "./receipt";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Lowercase hex SHA-256 of the gate-signed JWT that opens a receipt's SD-JWT; the same in every copy. */
export async function receiptHash(sd: string): Promise<string> {
  return sha256Hex(sd.split("~")[0]!);
}

// The certified action hash, read without checking the signature: the chain checks it next.
function actionHash(token: string): string | null {
  const segments = token.split(".");
  if (segments.length !== 3) return null;
  try {
    const payload: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromJwsSegment(segments[1]!)));
    if (!isObject(payload) || !isObject(payload.events)) return null;
    const subject = payload.events[EVENT_TYPE];
    return isObject(subject) && typeof subject.action_hash === "string" ? subject.action_hash : null;
  } catch {
    return null;
  }
}

/** Whether `hash` is the receipt's own hash or its certificate's action hash; false when either part does not read. */
export async function carries(r: Receipt, hash: string): Promise<boolean> {
  if (actionHash(r.certificate) === hash) return true;
  try {
    return (await receiptHash(r.sd)) === hash;
  } catch {
    return false;
  }
}
