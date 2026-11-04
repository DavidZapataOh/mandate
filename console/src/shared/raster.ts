export const PLATE_FACTOR = 6;

export interface Raster {
  readonly w: number;
  readonly h: number;
  readonly data: Uint8ClampedArray<ArrayBuffer>;
}

/** Repeats every pixel as a k by k block. */
export function upscale(r: Raster, k: number): Raster {
  const w = r.w * k;
  const h = r.h * k;
  const data = new Uint8ClampedArray(w * h * 4);
  for (let y = 0; y < h; y++) {
    const sy = Math.floor(y / k);
    for (let x = 0; x < w; x++) {
      const s = (sy * r.w + Math.floor(x / k)) * 4;
      data.set(r.data.subarray(s, s + 4), (y * w + x) * 4);
    }
  }
  return { w, h, data };
}

/** Inverse of upscale: refuses anything that is not a uniform k by k pixel grid. */
export function decimate(r: Raster, k: number): Raster {
  const bad = () => new Error(`raster: not a x${k} pixel grid`);
  if (r.w % k !== 0 || r.h % k !== 0) throw bad();
  const w = r.w / k;
  const h = r.h / k;
  const data = new Uint8ClampedArray(w * h * 4);
  for (let gy = 0; gy < h; gy++) {
    for (let gx = 0; gx < w; gx++) {
      const first = ((gy * k) * r.w + gx * k) * 4;
      for (let dy = 0; dy < k; dy++) {
        for (let dx = 0; dx < k; dx++) {
          const i = ((gy * k + dy) * r.w + gx * k + dx) * 4;
          for (let c = 0; c < 4; c++) if (r.data[i + c] !== r.data[first + c]) throw bad();
        }
      }
      data.set(r.data.subarray(first, first + 4), (gy * w + gx) * 4);
    }
  }
  return { w, h, data };
}
