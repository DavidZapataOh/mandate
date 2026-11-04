import { SPRITES, type DrawOp, type SpriteId } from "../world/sprites";
import type { ActorKind, Cue, SealInput, Venue } from "./cues";

export const DESK_X = 164;
export const DOOR_X = -20;
export const BOOTH_X = 207;
export const BANK_X = 300;
export const FLOOR_Y = 152;
export const DESK_FLOOR_Y = 136;
export const WALK_PX_S = 96;
export const RETREAT_PX_S = 144;
export const BOOTH_MS = 800;
export const VERDICT_HOLD_MS = 4000;
export const ALERT_HOLD_MS = 8000;
export const BUBBLE_MS = 3000;
export const QUEUE_MAX = 8;
export const VAULT_OPEN_MS = 1500;
export const WALK_FRAME_MS = 120;
export const AMBIENT_MS = { spark: 180, "code-team": 140, clerks: 400 } as const;

const ENVELOPE_OFFSET = 12;
const ENVELOPE_Y = 120;

export interface Walker {
  readonly cue: Cue;
  x: number;
  phase: "approach" | "at-booth" | "cross" | "retreat";
  since: number;
}

export type Anchor = "walker" | "spark" | "code" | "booth";

export interface Bubble {
  readonly seq: number;
  anchor: Anchor;
  tag: string;
  text: string;
  until: number;
}

export interface World {
  t: number;
  reducedMotion: boolean;
  queue: Cue[];
  walker: Walker | null;
  envelopeX: number | null;
  seal: SealInput;
  sealUntil: number;
  visitor: ActorKind | null;
  alert: string | null;
  alertUntil: number;
  vaultUntil: number;
  /** The venue whose delivery opened the vault or rack; the other venue's frame stays closed. */
  vaultVenue: Venue;
  /** An in-place verdict keeps the booth this long before the next visitor is let in. */
  holdUntil: number;
  bubbles: Bubble[];
  /** Which world fills the right-hand half. */
  venue: Venue;
}

export function createWorld(reducedMotion: boolean): World {
  return {
    t: 0,
    reducedMotion,
    queue: [],
    walker: null,
    envelopeX: null,
    seal: "wait",
    sealUntil: 0,
    visitor: null,
    alert: null,
    alertUntil: 0,
    vaultUntil: 0,
    vaultVenue: "bank",
    holdUntil: 0,
    bubbles: [],
    venue: "bank",
  };
}

function toward(x: number, target: number, pxPerS: number, dtMs: number): number {
  const step = (pxPerS * dtMs) / 1000;
  return x < target ? Math.min(target, x + step) : Math.max(target, x - step);
}

function setBubble(w: World, cue: Cue, anchor: Anchor): void {
  w.bubbles = w.bubbles.filter((b) => b.anchor !== anchor);
  w.bubbles.push({ seq: cue.seq, anchor, tag: cue.tag, text: cue.bubble, until: w.t + BUBBLE_MS });
}

function dropBubbles(w: World, anchors: readonly Anchor[]): void {
  w.bubbles = w.bubbles.filter((b) => !anchors.includes(b.anchor));
}

/** The booth shows only the verdict of the cue at its window: a new visitor resets seal and alert. */
function takeBooth(w: World, cue: Cue): void {
  dropBubbles(w, ["walker", "booth"]);
  w.visitor = cue.actor;
  // A breach has no verdict of its own and must never inherit a green seal.
  w.seal = cue.seal ?? "wait";
  w.sealUntil = w.t + VERDICT_HOLD_MS;
  w.alert = cue.alert;
  w.alertUntil = cue.alert === null ? 0 : w.t + ALERT_HOLD_MS;
}

function inPlaceAnchor(actor: ActorKind): Anchor {
  if (actor === "spark") return "spark";
  return actor === "code" ? "code" : "booth";
}

function actInPlace(w: World, cue: Cue): void {
  w.venue = cue.venue;
  takeBooth(w, cue);
  setBubble(w, cue, inPlaceAnchor(cue.actor));
  w.holdUntil = w.t + BOOTH_MS;
}

/** Shows the other world; refused (false) while a walker is out. */
export function setVenue(w: World, venue: Venue): boolean {
  if (w.walker !== null) return false;
  w.venue = venue;
  return true;
}

/**
 * Routes a cue. In-place cues with no verdict act now; one with a verdict acts now only if the
 * booth is free, else it waits its turn like a walker (the oldest beyond eight is dropped). A cue
 * of the other venue never changes the world under a walker: it waits too.
 */
export function pushCue(w: World, cue: Cue): void {
  if (cue.route === "none") {
    const idle = w.walker === null && w.queue.length === 0 && w.t >= w.holdUntil;
    if (cue.seal === null && (cue.venue === w.venue || idle)) {
      w.venue = cue.venue;
      setBubble(w, cue, inPlaceAnchor(cue.actor));
      return;
    }
    if (idle) {
      actInPlace(w, cue);
      return;
    }
  }
  w.queue.push(cue);
  // Chatter is only a bubble; it must never evict a cue that carries a verdict or a walker.
  while (w.queue.length > QUEUE_MAX) {
    const chatter = w.queue.findIndex((c) => c.route === "none" && c.seal === null);
    w.queue.splice(chatter === -1 ? 0 : chatter, 1);
  }
}

function openVault(w: World): void {
  w.vaultUntil = w.t + VAULT_OPEN_MS;
}

function arrive(w: World, walker: Walker): void {
  walker.x = BOOTH_X;
  walker.phase = "at-booth";
  walker.since = w.t;
  takeBooth(w, walker.cue);
  setBubble(w, walker.cue, "walker");
  if (walker.cue.bank) {
    w.vaultVenue = walker.cue.venue;
    if (w.reducedMotion) openVault(w);
    else w.envelopeX = BOOTH_X + ENVELOPE_OFFSET;
  }
}

function startWalker(w: World, cue: Cue): Walker {
  w.venue = cue.venue;
  const walker: Walker = { cue, x: cue.route === "desk" ? DESK_X : DOOR_X, phase: "approach", since: w.t };
  // The last visitor's bubble follows `w.walker`; it must not ride in on the next one.
  dropBubbles(w, ["walker"]);
  if (w.reducedMotion) arrive(w, walker);
  return walker;
}

function homeOf(cue: Cue): number {
  return cue.route === "desk" ? DESK_X : DOOR_X;
}

function isBreach(cue: Cue): boolean {
  return cue.outcome === "breach";
}

function moveWalker(w: World, walker: Walker, dt: number): void {
  if (walker.phase === "approach") {
    walker.x = toward(walker.x, BOOTH_X, WALK_PX_S, dt);
    if (walker.x === BOOTH_X) arrive(w, walker);
    return;
  }
  if (walker.phase === "at-booth") {
    if (w.reducedMotion) {
      if (walker.since < w.t) w.walker = null;
      return;
    }
    if (w.t - walker.since < BOOTH_MS) return;
    walker.phase = isBreach(walker.cue) ? "cross" : "retreat";
    walker.since = w.t;
  }
  if (walker.phase === "cross") {
    walker.x = toward(walker.x, BANK_X, WALK_PX_S, dt);
    if (walker.x === BANK_X) w.walker = null;
    return;
  }
  const speed = walker.cue.route === "desk" ? WALK_PX_S : RETREAT_PX_S;
  walker.x = toward(walker.x, homeOf(walker.cue), speed, dt);
  if (walker.x === homeOf(walker.cue)) w.walker = null;
}

/** Switches reduced motion; a walker or envelope in flight settles at once. */
export function setReducedMotion(w: World, on: boolean): void {
  w.reducedMotion = on;
  if (!on) return;
  const walker = w.walker;
  if (walker?.phase === "approach") arrive(w, walker);
  else if (walker) w.walker = null;
  if (w.envelopeX !== null) {
    w.envelopeX = null;
    openVault(w);
  }
}

/** Advances the simulation by `dtMs`. */
export function stepWorld(w: World, dtMs: number): void {
  w.t += dtMs;
  if (w.sealUntil > 0 && w.t >= w.sealUntil) {
    w.seal = "wait";
    w.visitor = null;
    w.sealUntil = 0;
  }
  if (w.alertUntil > 0 && w.t >= w.alertUntil) {
    w.alert = null;
    w.alertUntil = 0;
  }
  w.bubbles = w.bubbles.filter((b) => w.t < b.until);

  while (w.walker === null && w.t >= w.holdUntil) {
    const next = w.queue.shift();
    if (!next) break;
    if (next.route !== "none") w.walker = startWalker(w, next);
    else if (next.seal !== null) actInPlace(w, next);
    else {
      // A verdict-free cue that waited out a walker of the other world only speaks.
      w.venue = next.venue;
      setBubble(w, next, inPlaceAnchor(next.actor));
    }
  }
  if (w.walker) moveWalker(w, w.walker, dtMs);

  if (w.envelopeX !== null) {
    w.envelopeX = toward(w.envelopeX, BANK_X, WALK_PX_S, dtMs);
    if (w.envelopeX === BANK_X) {
      w.envelopeX = null;
      openVault(w);
    }
  }
}

/** The ambient frame (0-3) for a loop of `frameMs` per frame; frozen under reduced motion. */
export function ambientFrame(w: World, frameMs: number): number {
  return w.reducedMotion ? 0 : Math.floor(w.t / frameMs) % 4;
}

function vaultFrame(w: World): number {
  if (w.t >= w.vaultUntil || w.venue !== w.vaultVenue) return 0;
  if (w.reducedMotion) return 3;
  return Math.min(3, Math.floor((w.t - (w.vaultUntil - VAULT_OPEN_MS)) / 100) + 1);
}

function walkerSprite(actor: ActorKind): SpriteId {
  switch (actor) {
    case "thief":
    case "brute":
    case "forger":
    case "switcher":
      return actor;
    default:
      return "courier";
  }
}

const SIDE_ON_FRAMES: Partial<Record<SpriteId, readonly number[]>> = { thief: [1, 2, 3] };
const WALK_FRAMES = [0, 1, 2, 3] as const;

function walkerOp(w: World, walker: Walker): DrawOp {
  const sprite = walkerSprite(walker.cue.actor);
  const spec = SPRITES[sprite];
  const floor = walker.cue.route === "desk" ? DESK_FLOOR_Y : FLOOR_Y;
  const still = walker.phase === "at-booth" || w.reducedMotion;
  const cycle = SIDE_ON_FRAMES[sprite] ?? WALK_FRAMES;
  const step = Math.floor((w.t - walker.since) / WALK_FRAME_MS) % cycle.length;
  const op: DrawOp = {
    sprite,
    frame: still ? 4 : (cycle[step] as number),
    x: Math.round(walker.x - spec.w / 2),
    y: floor - spec.h,
    alpha: walker.cue.actor === "ghost" ? 0.5 : 1,
  };
  return walker.phase === "retreat" ? { ...op, flip: true } : op;
}

/** Everything to paint this frame, back to front. */
export function drawList(w: World): DrawOp[] {
  const op = (sprite: SpriteId, x: number, y: number, frame = 0): DrawOp => ({ sprite, frame, x, y, alpha: 1 });
  const hq = w.venue === "hq";
  const ops: DrawOp[] = [
    op("office", 0, 0),
    op(hq ? "hq" : "bank", 222, 0),
    op(hq ? "rack" : "vault", 391, 44, vaultFrame(w)),
    op("spark", 13, 94, ambientFrame(w, AMBIENT_MS.spark)),
    op("code-team", 56, 85, ambientFrame(w, AMBIENT_MS["code-team"])),
    op(hq ? "ops" : "clerks", 286, 89, ambientFrame(w, AMBIENT_MS.clerks)),
    op("booth", 181, 38),
  ];
  const deskWalk = w.walker?.cue.route === "desk";
  if (!deskWalk) ops.push(op("courier", 149, 89));
  if (w.walker) ops.push(walkerOp(w, w.walker));
  if (w.envelopeX !== null) ops.push(op("envelope", Math.round(w.envelopeX), ENVELOPE_Y));
  return ops;
}
