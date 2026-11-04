import { beforeEach, expect, test } from "vitest";
import type { SealPose } from "../booth/pose";
import { renderForensic } from "../forensic/drawer";
import { CONFIRM, HOSTILE } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import type { ConsoleLine } from "../wire/types";
import { denial } from "./__fixtures__/denials";
import { decorateForensic, type KillCam, mountKillCam } from "./view";

let aside: HTMLElement;
let opener: HTMLButtonElement;
let frames: Array<(now: number) => void>;
let poses: SealPose[];
let reduced: boolean;
let cam: KillCam;
let clock: number;

beforeEach(() => {
  document.body.innerHTML = '<button type="button" id="opener">KILL-CAM</button><aside id="killcam" hidden></aside><aside id="forensic" hidden></aside>';
  aside = document.getElementById("killcam")!;
  opener = document.getElementById("opener") as HTMLButtonElement;
  frames = [];
  poses = [];
  reduced = false;
  clock = 0;
  cam = mountKillCam(aside, {
    reducedMotion: () => reduced,
    frame: (cb) => frames.push(cb),
    cancel: () => {},
    paint: (_canvas: HTMLCanvasElement, _line: ConsoleLine, pose: SealPose) => {
      poses.push(pose);
    },
  });
});

const q = (sel: string) => aside.querySelector<HTMLElement>(sel)!;
const advance = (ms: number) => {
  clock += ms;
  const run = frames.splice(0);
  for (const cb of run) cb(clock);
};
const shown = () => [...aside.querySelectorAll<HTMLElement>("ol.steps li")].map((li) => [li.dataset.step, li.dataset.shown, li.querySelector(".word")!.textContent]);
const button = (name: string) => [...aside.querySelectorAll("button")].find((b) => b.textContent === name || b.getAttribute("aria-label") === name)!;

test("the tape opens on the first step and plays the payee swap to the policy rule that killed it", () => {
  expect(cam.open(denial("payee_swap"), opener)).toBe(true);
  expect(aside.hidden).toBe(false);
  expect(document.activeElement).toBe(q("h2"));
  expect(q("h2").textContent).toBe("Kill-cam · Line #4");
  expect(q(".timecode").textContent).toBe("CAM 01 · TELLER · 08:16:40 UTC · PLAYBACK · STEP 1/6");
  expect(q(".caption").textContent).toBe("Killed at Policy rule: recipient differs from intent");
  expect(q(".basis").textContent).toBe("Rebuilt from the forensic record of line #4; nothing is run again.");
  expect(shown()).toEqual([
    ["canonicalize", "true", "PASSED"],
    ["hash", "false", "…"],
    ["policy", "false", "…"],
    ["consent", "true", "NOT REACHED"],
    ["certificate", "true", "NOT REACHED"],
    ["bank", "true", "NOT REACHED"],
  ]);
  expect(button("Pause")).toBeDefined();
  advance(0);
  advance(900);
  advance(900);
  expect(q(".timecode").textContent).toBe("CAM 01 · TELLER · 08:16:40 UTC · PLAYBACK · STEP 3/6");
  expect(shown()[2]).toEqual(["policy", "true", "DENIED"]);
  expect(q('li[aria-current="step"]').dataset.step).toBe("policy");
  expect(q(".now").textContent).toBe("Step 3 of 6: Policy rule DENIED: recipient differs from intent");
  expect(button("Play")).toBeDefined();
  expect(poses.at(-1)?.seam).toBe("alert");
});

test("reduced motion opens paused on the failing step with the settled seal", () => {
  reduced = true;
  cam.open(denial("replay"), opener);
  advance(16);
  expect(q(".timecode").textContent).toBe("CAM 01 · TELLER · 08:16:40 UTC · PLAYBACK · STEP 6/6");
  expect(q('li[aria-current="step"]').dataset.step).toBe("bank");
  expect(button("Play")).toBeDefined();
  expect(poses.at(-1)).toEqual({ gap: 16, shakeX: 0, seam: "alert" });
});

test("step, scrub and play drive the tape from the keyboard-reachable controls", () => {
  reduced = true;
  cam.open(denial("replay"), opener);
  button("Previous step").click();
  expect(q(".timecode").textContent).toMatch(/STEP 5\/6$/);
  const scrub = q("input.scrub") as HTMLInputElement;
  expect([scrub.type, scrub.min, scrub.max, scrub.value, scrub.getAttribute("aria-label")]).toEqual(["range", "1", "6", "5", "Tape position"]);
  scrub.value = "2";
  scrub.dispatchEvent(new Event("input"));
  expect(q('li[aria-current="step"]').dataset.step).toBe("hash");
  button("Next step").click();
  expect(q('li[aria-current="step"]').dataset.step).toBe("policy");
  button("Play").click();
  expect(button("Pause")).toBeDefined();
});

test("Escape and Close put the tape away and return focus to its opener", () => {
  cam.open(denial("mcp_exfil"), opener);
  expect(q(".timecode").textContent).toBe("CAM 01 · TELLER · --:--:-- UTC · PLAYBACK · STEP 1/7");
  aside.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  expect([aside.hidden, document.activeElement]).toEqual([true, opener]);
  cam.open(denial("mcp_exfil"), opener);
  button("Close").click();
  expect([aside.hidden, document.activeElement]).toEqual([true, opener]);
});

test("opening another forensic line puts the tape away and moves focus to that drawer's heading", () => {
  const drawer = document.getElementById("forensic")!;
  renderForensic(drawer, denial("scope_escalation"));
  decorateForensic(drawer, denial("scope_escalation"), cam);
  drawer.querySelector<HTMLButtonElement>("button.killcam-open")!.click();
  expect(aside.hidden).toBe(false);
  renderForensic(drawer, denial("mcp_exfil"));
  decorateForensic(drawer, denial("mcp_exfil"), cam);
  const painted = poses.length;
  advance(16);
  expect([aside.hidden, poses.length]).toEqual([true, painted]);
  expect(document.activeElement).toBe(drawer.querySelector("h2"));
});

test("closing after the opener left the page returns focus to the fallback, not the detached button", () => {
  const ledger = document.createElement("ol");
  document.body.append(ledger);
  cam.open(denial("mcp_exfil"), opener);
  opener.remove();
  cam.close(ledger);
  expect([aside.hidden, document.activeElement]).toEqual([true, ledger]);
});

test("closing a tape that is not open leaves focus alone", () => {
  opener.focus();
  cam.close(document.body);
  expect(document.activeElement).toBe(opener);
});

test("what the attacker tried stays text", () => {
  cam.open(parseLine(HOSTILE), opener);
  expect(q(".tried").textContent).toBe('MANDATE_FIXTURE <img src=x onerror="window.pwned=1">');
  expect(aside.querySelector("img")).toBeNull();
});

test("a line that was not denied has no tape", () => {
  expect(cam.open(parseLine(CONFIRM), opener)).toBe(false);
  expect(aside.hidden).toBe(true);
});

test("the forensic drawer of a denial offers the kill-cam, a paid line's does not", () => {
  const drawer = document.getElementById("forensic")!;
  renderForensic(drawer, parseLine(CONFIRM));
  decorateForensic(drawer, parseLine(CONFIRM), cam);
  expect(drawer.querySelector("button.killcam-open")).toBeNull();
  renderForensic(drawer, denial("scope_escalation"));
  decorateForensic(drawer, denial("scope_escalation"), cam);
  const open = drawer.querySelector<HTMLButtonElement>("button.killcam-open")!;
  expect([open.textContent, open.previousElementSibling?.tagName]).toEqual(["KILL-CAM", "H2"]);
  open.click();
  expect(q(".caption").textContent).toBe("Killed at Broker: scope: target outside delegation");
  button("Close").click();
  expect(document.activeElement).toBe(open);
});
