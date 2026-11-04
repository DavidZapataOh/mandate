/** Largest clip the desk reads; twin of `swarm.voice.MAX_WAV_BYTES`. */
export const MAX_WAV_BYTES = 31_000_000;
/** Longest clip the desk transcribes; twin of `swarm.voice.MAX_AUDIO_S`. */
export const MAX_WAV_SECONDS = 600;

const RATES: readonly number[] = [16000, 24000];
const PCM = 1;

function refuse(detail: string): never {
  throw new Error(`unsupported wav: ${detail}`);
}

function tag(view: DataView, at: number): string {
  return String.fromCharCode(view.getUint8(at), view.getUint8(at + 1), view.getUint8(at + 2), view.getUint8(at + 3));
}

interface Format {
  channels: number;
  bits: number;
  rate: number;
}

/**
 * Refuses on this device a clip the desk's `check_wav` would refuse, in its
 * order: size, format, channels, sample width, rate, then duration.
 */
export function checkWav(buf: ArrayBuffer): { rate: number; seconds: number } {
  if (buf.byteLength > MAX_WAV_BYTES) refuse(`larger than ${MAX_WAV_BYTES} bytes`);
  const view = new DataView(buf);
  if (buf.byteLength < 12 || tag(view, 0) !== "RIFF" || tag(view, 8) !== "WAVE") refuse("not a wav file");
  let format: Format | null = null;
  let at = 12;
  while (at + 8 <= buf.byteLength) {
    const name = tag(view, at);
    const declared = view.getUint32(at + 4, true);
    const body = at + 8;
    if (name === "fmt ") {
      if (body + 16 > buf.byteLength || view.getUint16(body, true) !== PCM) refuse("not a wav file");
      format = { channels: view.getUint16(body + 2, true), rate: view.getUint32(body + 4, true), bits: view.getUint16(body + 14, true) };
    } else if (name === "data") {
      if (format === null) refuse("not a wav file");
      // The desk's `wave` reader counts the frames the chunk declares, even past
      // the end of the file, so a clip that claims ten minutes is refused here too.
      return measure(format, declared);
    }
    at = body + declared + (declared % 2);
  }
  return refuse("not a wav file");
}

function measure({ channels, bits, rate }: Format, dataBytes: number): { rate: number; seconds: number } {
  if (channels !== 1) refuse(`channels=${channels}`);
  const width = Math.floor((bits + 7) / 8);
  if (width !== 2) refuse(`sample width=${width}`);
  if (!RATES.includes(rate)) refuse(`rate=${rate}`);
  const frames = Math.floor(dataBytes / 2);
  if (frames > MAX_WAV_SECONDS * rate) refuse(`longer than ${MAX_WAV_SECONDS} s`);
  return { rate, seconds: frames / rate };
}

/** Mono 16-bit PCM WAV of `samples`, each clipped to [-1, 1]. */
export function encodeWav(samples: Float32Array, rate: number): ArrayBuffer {
  const data = samples.length * 2;
  const buf = new ArrayBuffer(44 + data);
  const view = new DataView(buf);
  const ascii = (at: number, text: string) => {
    for (let i = 0; i < text.length; i++) view.setUint8(at + i, text.charCodeAt(i));
  };
  ascii(0, "RIFF");
  view.setUint32(4, 36 + data, true);
  ascii(8, "WAVE");
  ascii(12, "fmt ");
  view.setUint32(16, 16, true);
  view.setUint16(20, PCM, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, rate, true);
  view.setUint32(28, rate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  ascii(36, "data");
  view.setUint32(40, data, true);
  samples.forEach((sample, i) => {
    const s = Math.max(-1, Math.min(1, sample));
    view.setInt16(44 + i * 2, s < 0 ? s * 0x8000 : s * 0x7fff, true);
  });
  return buf;
}
