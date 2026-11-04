import type { Raster } from "../src/shared/raster.ts";

/** Reads the RGBA PAM that ffmpeg writes; any other flavour is refused. */
export function readPam(bytes: Uint8Array): Raster {
  const end = new TextDecoder("latin1").decode(bytes.subarray(0, 256)).indexOf("ENDHDR\n");
  if (end < 0) throw new Error("pam: unsupported");
  const head = new TextDecoder("latin1").decode(bytes.subarray(0, end));
  const lines = head.split("\n");
  const field = (name: string): string | undefined =>
    lines.find((l) => l.startsWith(`${name} `))?.slice(name.length + 1);
  const w = Number(field("WIDTH"));
  const h = Number(field("HEIGHT"));
  if (lines[0] !== "P7" || field("DEPTH") !== "4" || field("MAXVAL") !== "255" || field("TUPLTYPE") !== "RGB_ALPHA") {
    throw new Error("pam: unsupported");
  }
  const body = bytes.subarray(end + "ENDHDR\n".length);
  if (!Number.isInteger(w) || !Number.isInteger(h) || w < 1 || h < 1 || body.length !== w * h * 4) {
    throw new Error("pam: unsupported");
  }
  return { w, h, data: new Uint8ClampedArray(body) };
}
