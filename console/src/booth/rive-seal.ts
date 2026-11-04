import type { SealInput } from "../scene/cues";
import type { SealEngine } from "./booth";
import { sealFrame } from "./canvas-seal";

/** Loads the Rive seal; rejects so the canvas seal stays when the file or runtime cannot load. */
export async function loadRiveSeal(
  canvas: HTMLCanvasElement,
  src: string,
  onState: (s: string) => void,
): Promise<SealEngine> {
  const { Alignment, Fit, Layout, Rive, RuntimeLoader } = await import("@rive-app/canvas");
  const wasm = await import("@rive-app/canvas/rive.wasm?url");
  RuntimeLoader.setWasmUrl(wasm.default);
  return new Promise<SealEngine>((resolve, reject) => {
    const rive: InstanceType<typeof Rive> = new Rive({
      src,
      canvas,
      stateMachines: "seal",
      autoplay: true,
      onLoad: () => {
        rive.resizeDrawingSurfaceToCanvas();
        // Same framing as the canvas seal: the refused halves fill the booth face.
        rive.layout = new Layout({
          fit: Fit.Contain,
          alignment: Alignment.Center,
          ...sealFrame(canvas.width, canvas.height),
        });
        resolve({
          name: "rive",
          fire(input: SealInput) {
            rive.stateMachineInputs("seal")?.find((i) => i.name === input)?.fire();
          },
        });
      },
      onLoadError: () => reject(new Error("seal: rive file failed to load")),
      onStateChange: (e) => {
        for (const s of Array.isArray(e.data) ? e.data : []) onState(String(s));
      },
    });
  });
}
