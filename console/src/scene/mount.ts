import "@fontsource/inter/latin-400.css";
import "@fontsource/inter/latin-700.css";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-700.css";
import "../console.css";
import { Booth, type SealEngine } from "../booth/booth";
import { CanvasSeal, sealFit } from "../booth/canvas-seal";
import { loadRiveSeal } from "../booth/rive-seal";
import { tally } from "../ledger/tally";
import type { LineStore } from "../store/store";
import { type Atlas, loadAtlas } from "./atlas";
import { cueFor } from "./cues";
import { LiveCues } from "./live";
import { FixedLoop, performanceClock } from "./loop";
import { ANCHOR, Overlay, stageX } from "./overlay";
import { blit } from "./render";
import { fitStage, type StageFit } from "./stage";
import { createWorld, drawList, pushCue, setReducedMotion, setVenue, stepWorld } from "./world";

/** Native top-left of the idle courier's tag, over the figure standing by the office door. */
const COURIER_TAG: readonly [number, number] = [145, 79];

function tagPoint(anchor: string | undefined): readonly [number, number] | undefined {
  if (anchor === "courier") return COURIER_TAG;
  return anchor === "spark" || anchor === "code" ? ANCHOR[anchor] : undefined;
}

const STAGE_LABEL = {
  bank: "Live branch: Meta's agents, the Mandate booth and the bank",
  hq: "Nimbus HQ: Meta's agents, the Mandate booth and production",
} as const;

function byId<T extends HTMLElement>(doc: Document, id: string): T {
  const el = doc.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
}

function context(canvas: HTMLCanvasElement): CanvasRenderingContext2D {
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("scene: no 2d context");
  return ctx;
}

/** Mounts the live world, the booth seal, the overlay and the counters on the console page. */
export function mountScene(
  doc: Document,
  store: LineStore,
  onOpen: (seq: number) => void,
): { hello(lastSeq: number): void; idle(): boolean } {
  const win = doc.defaultView ?? window;
  const base = import.meta.env.BASE_URL;
  void import("@fontsource/press-start-2p/latin-400.css");

  const root = doc.documentElement;
  const overlayEl = byId(doc, "overlay");
  const tags = [...overlayEl.querySelectorAll<HTMLElement>(".tag[data-anchor]")];
  // A phone widens its layout viewport around overflowing content; clamping to the
  // screen keeps that from feeding back into a desktop-sized stage.
  const measure = (): StageFit => {
    const el = doc.documentElement;
    const w = Math.min(el.clientWidth, win.visualViewport?.width ?? el.clientWidth, win.screen.width);
    const h = Math.min(el.clientHeight, win.visualViewport?.height ?? el.clientHeight, win.screen.height);
    return fitStage(Math.floor(w), Math.floor(h));
  };
  let fit: StageFit = measure();
  const applyFit = (): void => {
    fit = measure();
    root.style.setProperty("--scale", String(fit.scale));
    root.style.setProperty("--crop-x", `${fit.cropX}px`);
    root.style.setProperty("--stage-w", `${fit.width}px`);
    const widths = tags.map((tag) => tag.offsetWidth);
    tags.forEach((tag, i) => {
      const at = tagPoint(tag.dataset.anchor);
      // A cropped stage would cut a fixed tag at its edge; it slides inside like a bubble.
      if (at) tag.style.transform = `translate(${stageX(at[0], widths[i] ?? 0, fit)}px, ${at[1] * fit.scale}px)`;
    });
  };
  applyFit();
  // Tag widths settle once the mono face loads.
  void doc.fonts?.ready.then(applyFit);
  win.addEventListener("resize", applyFit);
  win.visualViewport?.addEventListener("resize", applyFit);

  const motion = win.matchMedia("(prefers-reduced-motion: reduce)");
  const world = createWorld(motion.matches);
  motion.addEventListener("change", (e) => setReducedMotion(world, e.matches));

  const worldCtx = context(byId<HTMLCanvasElement>(doc, "world"));
  let atlas: Atlas | null = null;
  void loadAtlas(base).then((loaded) => {
    atlas = loaded;
  });

  const boothEl = byId(doc, "booth");
  boothEl.dataset.visitor = "";
  const booth = new Booth(boothEl);
  const report = (state: string): void => booth.report(state);
  const sealCanvas = byId<HTMLCanvasElement>(doc, "seal");
  const sealCtx = context(sealCanvas);
  const canvasSeal = new CanvasSeal(sealCtx, report);
  let engine: SealEngine = canvasSeal;
  booth.adopt(canvasSeal);
  loadRiveSeal(sealCanvas, `${base}rive/seal.riv`, report).then(
    (rive) => {
      engine = rive;
      booth.adopt(rive);
    },
    () => undefined,
  );

  const live = new LiveCues();
  const verified = byId(doc, "c-verified");
  const denied = byId(doc, "c-denied");
  const p50 = byId(doc, "c-p50");
  store.subscribe((lines) => {
    for (const line of live.take(lines)) pushCue(world, cueFor(line));
    const t = tally(lines);
    verified.textContent = String(t.verified);
    denied.textContent = String(t.denied);
    p50.textContent = t.p50;
  });

  const overlay = new Overlay(overlayEl, onOpen);
  const courierTag = tags.find((t) => t.dataset.anchor === "courier");
  const alertEl = byId(doc, "alert");
  const stageEl = byId(doc, "stage");
  const venueButtons = { bank: byId<HTMLButtonElement>(doc, "venue-bank"), hq: byId<HTMLButtonElement>(doc, "venue-hq") };
  for (const venue of ["bank", "hq"] as const) {
    venueButtons[venue].addEventListener("click", () => {
      setVenue(world, venue);
    });
  }
  const setAttr = (el: HTMLElement, name: string, value: string): void => {
    if (el.getAttribute(name) !== value) el.setAttribute(name, value);
  };
  let shownAlert: string | null = null;
  const drawSeal = (): void => {
    const [k, dx, dy] = sealFit(sealCanvas.width, sealCanvas.height);
    sealCtx.clearRect(0, 0, sealCanvas.width, sealCanvas.height);
    sealCtx.setTransform(k, 0, 0, k, dx, dy);
    canvasSeal.draw(performanceClock.now());
    sealCtx.setTransform(1, 0, 0, 1, 0, 0);
  };

  new FixedLoop(performanceClock, {
    step: (dt) => stepWorld(world, dt),
    render: () => {
      if (atlas) blit(worldCtx, drawList(world), atlas);
      overlay.sync(world, fit);
      booth.set(world.seal);
      boothEl.dataset.visitor = world.visitor ?? "";
      // The idle courier leaves its spot while it walks a desk request, and its tag goes with it.
      const away = world.walker?.cue.route === "desk";
      if (courierTag && courierTag.hidden !== away) courierTag.hidden = away;
      setAttr(stageEl, "data-venue", world.venue);
      setAttr(stageEl, "aria-label", STAGE_LABEL[world.venue]);
      const busy = world.walker !== null;
      for (const venue of ["bank", "hq"] as const) {
        const button = venueButtons[venue];
        setAttr(button, "aria-pressed", String(world.venue === venue));
        if (button.disabled !== busy) button.disabled = busy;
      }
      if (world.alert !== shownAlert) {
        shownAlert = world.alert;
        alertEl.textContent = shownAlert ?? "";
        alertEl.hidden = shownAlert === null;
      }
      if (engine === canvasSeal) drawSeal();
    },
  }).start();

  return {
    hello: (lastSeq) => live.hello(lastSeq),
    // The booth has served every cue it was given: a replay may hand it the next line.
    idle: () => world.walker === null && world.queue.length === 0 && world.t >= world.holdUntil,
  };
}
