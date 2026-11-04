import type { SealPose } from "../booth/pose";
import { cellsOf } from "../ledger/narrate";
import type { ConsoleLine } from "../wire/types";
import { paintBooth } from "./paint";
import { killedAt, killSteps, type KillStep, type StepStatus } from "./steps";
import { openTape, pauseTape, playTape, seekTape, stepTape, tapeSeal, tickTape, type TapeState } from "./tape";

export interface KillCamOptions {
  reducedMotion(): boolean;
  frame?: (cb: (now: number) => void) => number;
  cancel?: (handle: number) => void;
  paint?: (canvas: HTMLCanvasElement, line: ConsoleLine, pose: SealPose) => void;
}

export interface KillCam {
  open(line: ConsoleLine, opener: HTMLElement | null): boolean;
  /** `fallback` takes focus when the opener is no longer on the page. */
  close(fallback?: HTMLElement | null): void;
}

const WORDS: Record<StepStatus, string> = { passed: "PASSED", failed: "DENIED", skipped: "SKIPPED", unreached: "NOT REACHED" };

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function button(label: string, onClick: () => void, name?: string): HTMLButtonElement {
  const b = el("button", undefined, label);
  b.type = "button";
  if (name) b.setAttribute("aria-label", name);
  b.addEventListener("click", onClick);
  return b;
}

/** Mount the tape drawer once; `open` fills it from a denied line. */
export function mountKillCam(aside: HTMLElement, opts: KillCamOptions): KillCam {
  const frame = opts.frame ?? ((cb) => requestAnimationFrame(cb));
  const cancel = opts.cancel ?? ((h) => cancelAnimationFrame(h));
  const paint = opts.paint ?? paintBooth;

  const heading = el("h2");
  heading.id = "killcam-title";
  heading.tabIndex = -1;
  const timecode = el("p", "timecode");
  const canvas = el("canvas", "tape");
  canvas.width = 150;
  canvas.height = 134;
  canvas.setAttribute("aria-hidden", "true");
  const frameBox = el("div", "tape-frame");
  frameBox.append(canvas);
  const basis = el("p", "basis");
  const caption = el("p", "caption");
  const tried = el("p", "tried");
  const list = el("ol", "steps");
  const playBtn = button("Play", () => {
    if (!tape || !steps) return;
    update(tape.playing ? pauseTape(tape) : playTape(tape));
  });
  const scrub = el("input", "scrub");
  scrub.type = "range";
  scrub.min = "1";
  scrub.step = "1";
  scrub.setAttribute("aria-label", "Tape position");
  scrub.addEventListener("input", () => {
    if (tape) update(seekTape(tape, Number(scrub.value)));
  });
  const controls = el("div", "controls");
  controls.append(
    button("‹", () => tape && update(stepTape(tape, -1)), "Previous step"),
    playBtn,
    button("›", () => tape && update(stepTape(tape, 1)), "Next step"),
    scrub,
  );
  const now = el("p", "now");
  now.setAttribute("role", "status");
  aside.setAttribute("aria-labelledby", "killcam-title");
  aside.append(heading, button("Close", () => close()), timecode, frameBox, basis, caption, tried, list, controls, now);

  let line: ConsoleLine | null = null;
  let steps: KillStep[] | null = null;
  let tape: TapeState | null = null;
  let opener: HTMLElement | null = null;
  let handle: number | null = null;
  let last: number | null = null;
  let loop = 0;
  let time = "";

  function render(): void {
    if (!tape || !steps) return;
    const { pos, total } = tape;
    timecode.textContent = `CAM 01 · TELLER · ${time} UTC · PLAYBACK · STEP ${pos}/${total}`;
    [...list.children].forEach((li, i) => {
      const s = steps?.[i];
      if (!(li instanceof HTMLElement) || !s) return;
      const shown = i < pos || s.status === "unreached";
      li.dataset["shown"] = String(shown);
      li.querySelector(".word")!.textContent = shown ? WORDS[s.status] : "…";
      if (i === pos - 1) li.setAttribute("aria-current", "step");
      else li.removeAttribute("aria-current");
    });
    const cur = steps[pos - 1];
    now.textContent = cur ? `Step ${pos} of ${total}: ${cur.title} ${WORDS[cur.status]}: ${cur.detail}` : "";
    playBtn.textContent = tape.playing ? "Pause" : "Play";
    scrub.value = String(pos);
  }

  function update(next: TapeState): void {
    tape = next;
    render();
  }

  function run(token: number): void {
    handle = frame((t) => {
      if (token !== loop || !tape || !line) return;
      const dt = last === null ? 0 : t - last;
      last = t;
      const prev = tape;
      tape = tickTape(prev, dt);
      if (tape.pos !== prev.pos || tape.playing !== prev.playing) render();
      paint(canvas, line, tapeSeal(tape, opts.reducedMotion()));
      run(token);
    });
  }

  function stop(): void {
    loop += 1;
    if (handle !== null) cancel(handle);
    handle = null;
  }

  function close(fallback?: HTMLElement | null): void {
    stop();
    if (aside.hidden) return;
    aside.hidden = true;
    const target = opener?.isConnected ? opener : (fallback ?? null);
    if (!target) return;
    if (!(target instanceof HTMLButtonElement) && !target.hasAttribute("tabindex")) target.tabIndex = -1;
    target.focus();
  }

  aside.addEventListener("keydown", (e) => {
    if (e.key === "Escape") close();
  });

  return {
    open(next, from) {
      const found = killSteps(next);
      if (!found) return false;
      stop();
      line = next;
      steps = found;
      opener = from;
      time = cellsOf(next).time;
      heading.textContent = `Kill-cam · Line #${next.seq}`;
      basis.textContent = `Rebuilt from the forensic record of line #${next.seq}; nothing is run again.`;
      caption.textContent = killedAt(found);
      tried.textContent = next.source === "attack" ? next.subject.narrative : "";
      list.replaceChildren(
        ...found.map((s) => {
          const li = el("li");
          li.dataset["step"] = s.id;
          li.dataset["status"] = s.status;
          li.append(el("span", "word"), " ", el("span", "title", s.title), el("span", "detail", s.detail));
          if (s.evidence !== null) {
            const pre = el("pre", "evidence", s.evidence);
            pre.title = s.evidence;
            li.append(pre);
          }
          return li;
        }),
      );
      tape = openTape(found, opts.reducedMotion());
      scrub.max = String(tape.end);
      last = null;
      render();
      aside.hidden = false;
      heading.focus();
      run(loop);
      return true;
    },
    close: (fallback) => close(fallback),
  };
}

/** Offer the tape from a forensic drawer when the line's record explains how it died. */
export function decorateForensic(drawer: HTMLElement, line: ConsoleLine, cam: KillCam): void {
  // The drawer was just rebuilt, so a tape still open belongs to the previous line and its opener is gone.
  cam.close(drawer.querySelector("h2"));
  if (killSteps(line) === null) return;
  const open = button("KILL-CAM", () => cam.open(line, open));
  open.classList.add("killcam-open");
  drawer.querySelector("h2")?.after(open);
}
