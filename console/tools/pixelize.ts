import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildPlate, type PlateSpec } from "./plate.ts";
import { encodePng } from "./png.ts";
import { readPam } from "./pam.ts";

interface Entry extends PlateSpec {
  model: string;
  request: string;
  prompt: string;
}

const here = new URL(".", import.meta.url).pathname;
const root = join(here, "..");

const { assets } = JSON.parse(readFileSync(join(here, "assets.json"), "utf8")) as { assets: Entry[] };
const wanted = process.argv.slice(2);
const dir = mkdtempSync(join(tmpdir(), "plate-"));
try {
  for (const spec of assets.filter((a) => wanted.length === 0 || wanted.includes(a.file))) {
    const tmp = join(dir, `${spec.file}.pam`);
    execFileSync("ffmpeg", ["-loglevel", "error", "-y", "-i", join(root, spec.raw), "-pix_fmt", "rgba", "-c:v", "pam", "-f", "image2", tmp]);
    writeFileSync(join(root, "public/world", spec.file), encodePng(buildPlate(readPam(readFileSync(tmp)), spec)));
    console.log(`wrote public/world/${spec.file}`);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
