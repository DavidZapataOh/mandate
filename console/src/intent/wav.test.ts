// @vitest-environment node
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { checkWav, encodeWav } from "./wav";

const CLIP = new URL("../../../demo/voice/pay-acme.wav", import.meta.url);

function wav(seconds: number, rate = 16000, channels = 1, bits = 16): ArrayBuffer {
  const buf = encodeWav(new Float32Array(Math.round(seconds * rate)), rate);
  const view = new DataView(buf);
  view.setUint16(22, channels, true);
  view.setUint16(34, bits, true);
  return buf;
}

/** A clip whose data chunk declares `frames` frames whatever it holds. */
function declaring(seconds: number, frames: number): ArrayBuffer {
  const buf = wav(seconds);
  new DataView(buf).setUint32(40, frames * 2, true);
  return buf;
}

describe("checkWav", () => {
  it("accepts the demo clip as the desk does", () => {
    const bytes = readFileSync(CLIP);
    const clip = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    expect(checkWav(clip)).toEqual({ rate: 24000, seconds: 131170 / 24000 });
  });

  it("accepts exactly ten minutes", () => {
    expect(checkWav(wav(600)).seconds).toBe(600);
  });

  it.each([
    ["a clip over ten minutes", wav(600 + 1 / 16000), "unsupported wav: longer than 600 s"],
    ["a file over the upload cap", new ArrayBuffer(31_000_001), "unsupported wav: larger than 31000000 bytes"],
    ["stereo", wav(1, 16000, 2), "unsupported wav: channels=2"],
    ["8-bit samples", wav(1, 16000, 1, 8), "unsupported wav: sample width=1"],
    ["44.1 kHz", wav(1, 44100), "unsupported wav: rate=44100"],
    ["text", new TextEncoder().encode("RIFFnope").buffer, "unsupported wav: not a wav file"],
    ["a one-second clip that declares over ten minutes, as the desk counts it", declaring(1, 600 * 16000 + 1), "unsupported wav: longer than 600 s"],
  ])("refuses %s", (_name, buf, message) => {
    expect(() => checkWav(buf)).toThrow(message);
  });
});

describe("encodeWav", () => {
  it("writes clipped 16-bit mono PCM", () => {
    const view = new DataView(encodeWav(Float32Array.of(0, 1, -1, 1.03, -2), 16000));
    const samples = [0, 1, 2, 3, 4].map((i) => view.getInt16(44 + i * 2, true));
    expect(samples).toEqual([0, 32767, -32768, 32767, -32768]);
    expect([view.getUint32(24, true), view.getUint32(40, true), view.byteLength]).toEqual([16000, 10, 54]);
  });
});
