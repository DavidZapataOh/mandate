import { expect, test } from "vitest";
import RML from "../../rive/seal/scene.rml?raw";

const doc = new DOMParser().parseFromString(RML, "application/xml");
const FPS = 60;
const PROP = { x: "13", y: "14", opacity: "18" } as const;
const SHAPE = { top: "0:20", seam: "0:22", alert: "0:23" } as const;

function animation(name: string): Element {
  const found = [...doc.querySelectorAll("LinearAnimation")].find((a) => a.getAttribute("name") === name);
  if (found === undefined) throw new Error(`no animation ${name}`);
  return found;
}

/** [frame, value, interpolation] keyframes of one shape property inside an animation. */
function keys(anim: Element, shape: string, prop: string): [number, number, string][] {
  return [...anim.querySelectorAll(`KeyedObject[objectId="${shape}"] > KeyedProperty[propertyKey="${prop}"] > KeyFrameDouble`)].map((k) => [
    Number(k.getAttribute("frame")),
    Number(k.getAttribute("value")),
    k.getAttribute("interpolationType") ?? "",
  ]);
}

const ms = (frame: number): number => Math.round((frame * 1000) / FPS);

test("the seam snap closes the halves in 133 ms and stops dead", () => {
  const verify = animation("verify");
  expect(verify.getAttribute("fps") ?? String(FPS)).toBe("60");
  expect(verify.getAttribute("loopValue")).toBeNull();
  expect(ms(Number(verify.getAttribute("duration")))).toBe(133);
  expect(keys(verify, SHAPE.top, PROP.y)).toEqual([
    [0, -8, "linear"],
    [8, 0, "linear"],
  ]);
});

test("the mismatch parts the halves in 100 ms and shakes four 80 ms beats", () => {
  const deny = animation("deny");
  expect(keys(deny, SHAPE.top, PROP.y).map(([f, v]) => [ms(f), v])).toEqual([
    [0, -8],
    [100, -16],
  ]);
  const shake = keys(deny, SHAPE.top, PROP.x);
  expect(shake.map(([, v, i]) => [v, i])).toEqual([
    [-6, "hold"],
    [6, "hold"],
    [-6, "hold"],
    [6, "hold"],
    [0, "hold"],
  ]);
  const beats = shake.map(([f]) => ms(f));
  [0, 80, 160, 240, 320].forEach((want, i) => expect(Math.abs(beats[i]! - want)).toBeLessThanOrEqual(ms(1)));
});

test("green lights only on the snap and the alert bar only on the mismatch", () => {
  const lit = (anim: string, shape: string) => keys(animation(anim), shape, PROP.opacity).map(([, v]) => v);
  expect([lit("verify", SHAPE.seam), lit("verify", SHAPE.alert)]).toEqual([[1], [0]]);
  expect([lit("deny", SHAPE.seam), lit("deny", SHAPE.alert)]).toEqual([[0], [1]]);
  expect([lit("wait", SHAPE.seam), lit("wait", SHAPE.alert)]).toEqual([[0], [0]]);
});
