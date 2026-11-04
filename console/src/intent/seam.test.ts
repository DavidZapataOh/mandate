import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("holder page funds-proof line", () => {
  const html = readFileSync(resolve(process.cwd(), "holder.html"), "utf8");

  it("says the desk signs over the balance its bank reports, on any rail", () => {
    expect(html).toContain(
      "Funds proof: a statement the desk signs over the balance its bank reports (cooperative). zkTLS is not used for this bank.",
    );
    expect(html).not.toMatch(/simulated bank/i);
  });
});
