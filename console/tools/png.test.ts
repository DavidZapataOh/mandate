import { expect, test } from "vitest";
import { crc32, inflateSync } from "node:zlib";
import { encodePng } from "./png.ts";
import { readPam } from "./pam.ts";

function chunks(png: Uint8Array): { type: string; body: Uint8Array; crcOk: boolean }[] {
  const v = new DataView(png.buffer, png.byteOffset);
  const out = [];
  for (let o = 8; o < png.length; ) {
    const len = v.getUint32(o);
    const type = new TextDecoder().decode(png.subarray(o + 4, o + 8));
    const body = png.subarray(o + 8, o + 8 + len);
    out.push({ type, body, crcOk: v.getUint32(o + 8 + len) === crc32(png.subarray(o + 4, o + 8 + len)) });
    o += len + 12;
  }
  return out;
}

test("encodePng writes an RGBA image whose scanlines inflate to the pixels", () => {
  const png = encodePng({ w: 2, h: 1, data: new Uint8ClampedArray([255, 0, 0, 255, 0, 0, 0, 0]) });
  expect(Array.from(png.subarray(0, 8))).toEqual([137, 80, 78, 71, 13, 10, 26, 10]);
  const [ihdr, idat, iend] = chunks(png);
  expect(ihdr?.type).toBe("IHDR");
  expect(Array.from(ihdr!.body)).toEqual([0, 0, 0, 2, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
  expect(Array.from(inflateSync(idat!.body))).toEqual([0, 255, 0, 0, 255, 0, 0, 0, 0]);
  expect(iend?.type).toBe("IEND");
  expect([ihdr, idat, iend].every((c) => c?.crcOk)).toBe(true);
});

test("readPam reads the RGBA tuples ffmpeg writes", () => {
  const head = new TextEncoder().encode("P7\nWIDTH 1\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nTUPLTYPE RGB_ALPHA\nENDHDR\n");
  const r = readPam(new Uint8Array([...head, 9, 13, 23, 255]));
  expect([r.w, r.h, Array.from(r.data)]).toEqual([1, 1, [9, 13, 23, 255]]);
});

test("readPam refuses a file that is not RGBA PAM", () => {
  const head = new TextEncoder().encode("P7\nWIDTH 1\nHEIGHT 1\nDEPTH 3\nMAXVAL 255\nTUPLTYPE RGB\nENDHDR\n");
  expect(() => readPam(new Uint8Array([...head, 9, 13, 23]))).toThrow("pam: unsupported");
});
