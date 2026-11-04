import { decimate, PLATE_FACTOR } from "../shared/raster";
import { SPRITES, type SpriteId } from "../world/sprites";

export type Atlas = ReadonlyMap<SpriteId, readonly HTMLCanvasElement[]>;

async function loadFrame(url: string): Promise<HTMLCanvasElement> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`atlas: ${url} ${res.status}`);
  const bitmap = await createImageBitmap(await res.blob());
  const src = document.createElement("canvas");
  src.width = bitmap.width;
  src.height = bitmap.height;
  const sctx = src.getContext("2d", { willReadFrequently: true });
  if (!sctx) throw new Error("atlas: no 2d context");
  sctx.drawImage(bitmap, 0, 0);
  bitmap.close();
  const img = sctx.getImageData(0, 0, src.width, src.height);
  const native = decimate({ w: img.width, h: img.height, data: img.data }, PLATE_FACTOR);
  const out = document.createElement("canvas");
  out.width = native.w;
  out.height = native.h;
  const octx = out.getContext("2d");
  if (!octx) throw new Error("atlas: no 2d context");
  octx.putImageData(new ImageData(native.data, native.w, native.h), 0, 0);
  return out;
}

export async function loadAtlas(base: string): Promise<Atlas> {
  const ids = Object.keys(SPRITES) as SpriteId[];
  const entries = await Promise.all(
    ids.map(async (id) => {
      const frames = await Promise.all(SPRITES[id].frames.map((f) => loadFrame(`${base}${f}`)));
      return [id, frames] as const;
    }),
  );
  return new Map(entries);
}
