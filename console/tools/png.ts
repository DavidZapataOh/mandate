import { crc32, deflateSync } from "node:zlib";
import type { Raster } from "../src/shared/raster.ts";

const SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];

function chunk(type: string, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(12 + body.length);
  const v = new DataView(out.buffer);
  v.setUint32(0, body.length);
  out.set(new TextEncoder().encode(type), 4);
  out.set(body, 8);
  v.setUint32(8 + body.length, crc32(out.subarray(4, 8 + body.length)));
  return out;
}

/** Encodes 8-bit RGBA with filter 0 on every scanline. */
export function encodePng(r: Raster): Uint8Array {
  const ihdr = new Uint8Array(13);
  const hv = new DataView(ihdr.buffer);
  hv.setUint32(0, r.w);
  hv.setUint32(4, r.h);
  ihdr.set([8, 6, 0, 0, 0], 8);
  const stride = r.w * 4;
  const raw = new Uint8Array((stride + 1) * r.h);
  for (let y = 0; y < r.h; y++) raw.set(r.data.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1);
  const parts = [
    new Uint8Array(SIGNATURE),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", new Uint8Array(0)),
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
