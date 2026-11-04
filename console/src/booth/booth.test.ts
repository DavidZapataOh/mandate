import { expect, test } from "vitest";
import type { SealInput } from "../scene/cues";
import { Booth, type SealEngine } from "./booth";

class RecordingEngine implements SealEngine {
  readonly fired: SealInput[] = [];
  constructor(readonly name: "rive" | "canvas") {}
  fire(input: SealInput): void {
    this.fired.push(input);
  }
}

test("the booth fires each seal input once per change", () => {
  const booth = new Booth(document.createElement("div"));
  const engine = new RecordingEngine("canvas");
  booth.adopt(engine);
  booth.set("deny");
  booth.set("deny");
  booth.set("wait");
  expect(engine.fired).toEqual(["deny", "wait"]);
});

test("a late-loading engine takes over the current verdict", () => {
  const host = document.createElement("div");
  const booth = new Booth(host);
  booth.adopt(new RecordingEngine("canvas"));
  booth.set("verify");
  const rive = new RecordingEngine("rive");
  booth.adopt(rive);
  expect(rive.fired).toEqual(["verify"]);
  expect(host.dataset.sealEngine).toBe("rive");
});

test("the booth element shows the state the engine reports, not the one requested", () => {
  const host = document.createElement("div");
  const booth = new Booth(host);
  booth.adopt(new RecordingEngine("rive"));
  booth.set("deny");
  expect(host.dataset.seal).toBe("wait");
  booth.report("deny");
  expect(host.dataset.seal).toBe("deny");
});
