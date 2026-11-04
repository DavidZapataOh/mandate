export const NATIVE_W = 444;
export const NATIVE_H = 164;
export const STAGE_SHARE = 0.66;

export interface StageFit {
  scale: number;
  width: number;
  height: number;
  cropX: number;
}

export function fitStage(viewW: number, viewH: number): StageFit {
  const byHeight = Math.floor(Math.floor(viewH * STAGE_SHARE) / NATIVE_H);
  const byWidth = Math.ceil(viewW / NATIVE_W);
  const scale = Math.max(2, Math.min(byHeight, byWidth));
  return {
    scale,
    width: Math.min(NATIVE_W * scale, viewW),
    height: NATIVE_H * scale,
    cropX: Math.max(0, Math.floor((NATIVE_W * scale - viewW) / 2)),
  };
}
