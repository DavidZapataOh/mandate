import { type Bytes, concat, sha256, toHex } from "./bytes";

/** One attestation of a proof; `msg` is the lowercase hex of the message it commits. */
export type Attestation = { kind: "pending"; uri: string; msg: string } | { kind: "bitcoin"; height: number; msg: string };

/** A parsed OpenTimestamps proof: the digest it starts from and every attestation it reaches. */
export interface OtsProof {
  digest: string;
  attestations: Attestation[];
}

/** A proof the reader refuses; the message is the reason. */
export class OtsError extends Error {
  override name = "OtsError";
}

/** Largest proof the reader accepts, in bytes. */
export const MAX_PROOF_BYTES = 32768;

/** Easiest proof-of-work target a header may claim. */
export const WORK_FLOOR = 2n ** 180n;

const MAGIC = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294";
const MAGIC_LEN = MAGIC.length / 2;
const PENDING = "83dfe30d2ef90c8e";
const BITCOIN = "0588960d73d71901";
const MAX_DEPTH = 256;
const MAX_ARG = 4096;
const MAX_PAYLOAD = 8192;
const MAX_URI = 1000;
const MAX_HEIGHT = 0xffffffffn;
const URI_CHARS = /^[A-Za-z0-9._/:-]*$/;

class Reader {
  private at = 0;

  constructor(private readonly bytes: Bytes) {}

  get done(): boolean {
    return this.at === this.bytes.length;
  }

  byte(): number {
    const b = this.bytes[this.at];
    if (b === undefined) throw new OtsError("truncated");
    this.at += 1;
    return b;
  }

  take(n: number): Bytes {
    if (this.at + n > this.bytes.length) throw new OtsError("truncated");
    const out = this.bytes.slice(this.at, this.at + n);
    this.at += n;
    return out;
  }

  varuint(): bigint {
    let value = 0n;
    for (let i = 0; i < 9; i++) {
      const b = this.byte();
      value |= BigInt(b & 0x7f) << BigInt(7 * i);
      if (!(b & 0x80)) return value;
    }
    throw new OtsError("varuint too long");
  }

  varbytes(max: number, min = 0): Bytes {
    const n = this.varuint();
    if (n < BigInt(min) || n > BigInt(max)) throw new OtsError("bad length");
    return this.take(Number(n));
  }
}

function attestation(tag: string, payload: Bytes, msg: Bytes): Attestation | null {
  const r = new Reader(payload);
  let found: Attestation | null = null;
  try {
    if (tag === PENDING) {
      const uri = new TextDecoder("utf-8", { fatal: true }).decode(r.varbytes(MAX_URI));
      if (!URI_CHARS.test(uri)) throw new OtsError("attestation malformed");
      found = { kind: "pending", uri, msg: toHex(msg) };
    } else if (tag === BITCOIN) {
      const height = r.varuint();
      if (height > MAX_HEIGHT) throw new OtsError("attestation malformed");
      found = { kind: "bitcoin", height: Number(height), msg: toHex(msg) };
    } else {
      return null;
    }
  } catch {
    throw new OtsError("attestation malformed");
  }
  if (!r.done) throw new OtsError("attestation malformed");
  return found;
}

async function walk(r: Reader, msg: Bytes, depth: number, out: Attestation[]): Promise<void> {
  // Upstream counts its limit down from 256 and stops at 0, so at most 255 operations nest.
  if (depth >= MAX_DEPTH) throw new OtsError("too deep");
  const seen = new Set<string>();
  let tag = r.byte();
  while (tag === 0xff) {
    await branch(r, r.byte(), msg, depth, out, seen);
    tag = r.byte();
  }
  await branch(r, tag, msg, depth, out, seen);
}

// Only the operations calendars emit today are verified, so anything else is refused, never skipped.
async function branch(
  r: Reader,
  tag: number,
  msg: Bytes,
  depth: number,
  out: Attestation[],
  seen: Set<string>,
): Promise<void> {
  if (tag === 0x00) {
    const kind = toHex(r.take(8));
    const found = attestation(kind, r.varbytes(MAX_PAYLOAD), msg);
    if (found) out.push(found);
    return;
  }
  let next: Bytes;
  let op: string;
  if (tag === 0x08) {
    op = "08";
    next = await sha256(msg);
  } else if (tag === 0xf0 || tag === 0xf1) {
    const arg = r.varbytes(MAX_ARG, 1);
    op = `${tag.toString(16)}${toHex(arg)}`;
    next = tag === 0xf0 ? concat(msg, arg) : concat(arg, msg);
  } else {
    throw new OtsError(`unsupported operation 0x${tag.toString(16).padStart(2, "0")}`);
  }
  // Upstream refuses a node with the same operation on two branches.
  if (seen.has(op)) throw new OtsError("repeated operation");
  seen.add(op);
  if (next.length > MAX_ARG) throw new OtsError("bad length");
  await walk(r, next, depth + 1, out);
}

/** Parse a detached `.ots` proof over a SHA-256 digest and collect its attestations. */
export async function readOts(proof: Bytes): Promise<OtsProof> {
  if (proof.length > MAX_PROOF_BYTES) throw new OtsError("proof too large");
  if (proof.length < MAGIC_LEN || toHex(proof.slice(0, MAGIC_LEN)) !== MAGIC) {
    throw new OtsError("not an OpenTimestamps proof");
  }
  const r = new Reader(proof.slice(MAGIC_LEN));
  const version = r.varuint();
  if (version !== 1n) throw new OtsError(`unsupported version ${version}`);
  if (r.byte() !== 0x08) throw new OtsError("not a SHA-256 proof");
  const digest = r.take(32);
  const attestations: Attestation[] = [];
  await walk(r, digest, 0, attestations);
  if (!r.done) throw new OtsError("trailing bytes");
  return { digest: toHex(digest), attestations };
}

/** What an 80-byte Bitcoin block header proves on its own. */
export interface BlockHeader {
  hash: string;
  merkleRoot: string;
  time: number;
  meetsTarget: boolean;
  aboveFloor: boolean;
}

function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i] ?? 0);
  return value;
}

function target(bits: number): bigint {
  const exponent = bits >>> 24;
  const mantissa = BigInt(bits & 0x007fffff);
  if (bits & 0x00800000 || mantissa === 0n) return 0n;
  if (exponent < 3) return mantissa >> BigInt(8 * (3 - exponent));
  return mantissa << BigInt(8 * (exponent - 3));
}

/** Read a block header's hash, merkle root and time, and check its proof of work and the work floor. */
export async function readHeader(header: Bytes): Promise<BlockHeader> {
  if (header.length !== 80) throw new Error("header: a block header is 80 bytes");
  const digest = await sha256(await sha256(header));
  const goal = target(Number(littleEndian(header.subarray(72, 76))));
  return {
    hash: toHex(digest.slice().reverse()),
    merkleRoot: toHex(header.subarray(36, 68)),
    time: Number(littleEndian(header.subarray(68, 72))),
    meetsTarget: littleEndian(digest) <= goal,
    aboveFloor: goal <= WORK_FLOOR,
  };
}
