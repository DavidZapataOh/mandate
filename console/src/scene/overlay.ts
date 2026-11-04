import type { StageFit } from "./stage";
import { BOOTH_X, FLOOR_Y, type Anchor, type Bubble, type World } from "./world";

export const ANCHOR: Record<Exclude<Anchor, "walker">, readonly [number, number]> = {
  spark: [6, 79],
  code: [72, 87],
  booth: [196, 30],
};
export const WALKER_TAG_Y = FLOOR_Y - 16;
/** CSS px a bubble keeps from the stage edge; matches the bubble's max-width allowance. */
const INSET = 8;
/** Native tops of the alert bar and the booth's TELLER sign: these bubbles end above them. */
const CEILING: Partial<Record<Anchor, number>> = { walker: 151, booth: 38 + 9 };
const CEILING_GAP = 4;

/** CSS left of a box of `width` at native `x` (less `shift` CSS px), kept `INSET` inside a cropped stage. */
export function stageX(x: number, width: number, fit: StageFit, shift = 0): number {
  return Math.max(INSET, Math.min(Math.round(x * fit.scale - fit.cropX - shift), fit.width - INSET - width));
}

export interface PlacedTag {
  readonly tag: HTMLElement;
  readonly x: number;
  readonly y: number;
  readonly w: number;
  readonly h: number;
  /** Native distance from the booth. */
  readonly near: number;
}

/**
 * Places the fixed tags nearest the booth first. A tag that would overlap one already placed gives way:
 * a repeated name hides, a name not yet shown steps up or down by its own height plus 4 px, inside the stage.
 * Returns the boxes shown.
 */
export function placeTags(placed: readonly PlacedTag[], stageHeight: number): PlacedTag[] {
  const shown: PlacedTag[] = [];
  const names = new Set<string>();
  const hits = (b: PlacedTag): boolean => shown.some((s) => b.x < s.x + s.w && s.x < b.x + b.w && b.y < s.y + s.h && s.y < b.y + b.h);
  for (const p of [...placed].sort((a, b) => a.near - b.near)) {
    // A tag not rendered (its figure is away) neither shows its name nor blocks another.
    if (p.w === 0 || p.h === 0) continue;
    const name = p.tag.textContent ?? "";
    let box: PlacedTag | null = p;
    if (hits(p)) {
      box = null;
      // The same name already reads nearer the booth; a different one moves rather than vanish.
      if (!names.has(name)) {
        const step = p.h + 4;
        for (let k = 1; k <= 4 && box === null; k += 1) {
          for (const y of [p.y - k * step, p.y + k * step]) {
            const moved = { ...p, y };
            if (y >= 0 && y + p.h <= stageHeight && !hits(moved)) {
              box = moved;
              break;
            }
          }
        }
      }
    }
    if (box === null) {
      p.tag.style.visibility = "hidden";
      continue;
    }
    p.tag.style.visibility = "";
    p.tag.style.transform = `translate(${box.x}px, ${box.y}px)`;
    shown.push(box);
    names.add(name);
  }
  return shown;
}

/** Native position of a bubble's anchor. */
export function anchorPoint(anchor: Anchor, w: World): readonly [number, number] {
  if (anchor === "walker") return [w.walker?.x ?? BOOTH_X, WALKER_TAG_Y];
  return ANCHOR[anchor];
}

function make(bubble: Bubble, onOpen: (seq: number) => void): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "bubble";
  button.dataset.seq = String(bubble.seq);
  button.dataset.anchor = bubble.anchor;
  button.setAttribute("aria-label", `${bubble.tag}: ${bubble.text}`);
  const tag = document.createElement("span");
  tag.className = "tag";
  tag.textContent = bubble.tag;
  const say = document.createElement("span");
  say.className = "say";
  say.textContent = bubble.text;
  button.append(tag, say);
  button.addEventListener("click", () => onOpen(bubble.seq));
  return button;
}

/** Sentence bubbles over the stage: one button per live bubble, moved with composite-only transforms. */
export class Overlay {
  private readonly live = new Map<Bubble, HTMLButtonElement>();

  constructor(
    private readonly root: HTMLElement,
    private readonly onOpen: (seq: number) => void,
  ) {}

  sync(w: World, fit: StageFit): void {
    for (const [bubble, el] of this.live) {
      if (!w.bubbles.includes(bubble)) {
        el.remove();
        this.live.delete(bubble);
      }
    }
    const placed: [HTMLButtonElement, Bubble][] = [];
    for (const bubble of w.bubbles) {
      let el = this.live.get(bubble);
      if (!el) {
        el = make(bubble, this.onOpen);
        this.live.set(bubble, el);
        this.root.append(el);
      }
      placed.push([el, bubble]);
    }
    // All boxes are read before any transform is written, so a frame costs one layout.
    const boxes = placed.map(([el]) => [el.offsetWidth, el.offsetHeight] as const);
    placed.forEach(([el, bubble], i) => {
      const [width, height] = boxes[i] ?? [0, 0];
      const [x, y] = anchorPoint(bubble.anchor, w);
      // A walker's bubble straddles the figure; on a cropped stage it slides to stay whole.
      const centre = bubble.anchor === "walker" ? width / 2 : 0;
      const left = stageX(x, width, fit, centre);
      const ceiling = CEILING[bubble.anchor];
      // A second line grows the bubble upward, never over the alert bar or the sign.
      const top = ceiling === undefined ? Math.round(y * fit.scale) : Math.max(0, Math.min(Math.round(y * fit.scale), ceiling * fit.scale - CEILING_GAP - height));
      el.style.transform = `translate(${left}px, ${top}px)`;
    });
  }
}
