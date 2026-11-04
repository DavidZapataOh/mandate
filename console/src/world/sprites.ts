export type SpriteId =
  | "office"
  | "bank"
  | "hq"
  | "rack"
  | "ops"
  | "booth"
  | "vault"
  | "spark"
  | "code-team"
  | "clerks"
  | "courier"
  | "thief"
  | "brute"
  | "forger"
  | "switcher"
  | "envelope";

export interface SpriteSpec {
  readonly w: number;
  readonly h: number;
  readonly frames: readonly string[];
}

// Frame 0 is the shipped plate; later frames sit beside it as `<name>-<n>.png`.
function sprite(plate: string, w: number, h: number, count: number): SpriteSpec {
  const frames = Array.from({ length: count }, (_, i) =>
    i === 0 ? plate : plate.replace(/\.png$/, `-${i}.png`),
  );
  return { w, h, frames };
}

// Walkers: frames 0-3 are the walk cycle, frame 4 is the pose at the booth.
export const SPRITES: Record<SpriteId, SpriteSpec> = {
  office: sprite("world/office.png", 222, 164, 1),
  bank: sprite("world/bank.png", 222, 164, 1),
  hq: sprite("world/hq.png", 222, 164, 1),
  rack: sprite("world/rack.png", 53, 63, 4),
  ops: sprite("world/ops.png", 90, 23, 4),
  booth: sprite("world/booth.png", 82, 107, 1),
  vault: sprite("world/vault.png", 53, 63, 4),
  spark: sprite("world/spark.png", 30, 28, 4),
  "code-team": sprite("world/code-team.png", 90, 50, 4),
  clerks: sprite("world/clerks.png", 90, 23, 4),
  courier: sprite("world/courier.png", 30, 47, 5),
  thief: sprite("world/thief.png", 42, 60, 5),
  brute: sprite("world/brute.png", 44, 60, 5),
  forger: sprite("world/forger.png", 34, 50, 5),
  switcher: sprite("world/switcher.png", 34, 50, 5),
  envelope: sprite("world/envelope.png", 10, 8, 1),
};

export interface DrawOp {
  readonly sprite: SpriteId;
  readonly frame: number;
  readonly x: number;
  readonly y: number;
  /** Mirrored horizontally (a walker heading left); absent means as drawn. */
  readonly flip?: boolean;
  readonly alpha: number;
}
