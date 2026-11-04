import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("holder page funds-proof line", () => {
  const html = readFileSync(resolve(process.cwd(), "holder.html"), "utf8");

  it("names both funds paths and what the zkTLS path reveals", () => {
    expect(html).toContain(
      "Funds proof: a statement the desk signs over the balance its bank reports (cooperative). On the sandbox rail, run mandate-holder-proof to add a zkTLS proof of your Increase balance; Mandate's verifier sees the balance and checks it covers the payment.",
    );
    expect(html).not.toContain("zkTLS is not used");
    expect(html).not.toMatch(/simulated bank/i);
  });
});
