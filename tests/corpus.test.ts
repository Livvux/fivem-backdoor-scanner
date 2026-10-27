import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { securityRules } from "../src/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const positiveDir = join(root, "corpus/positive");
const negativeDir = join(root, "corpus/negative");

describe("corpus", () => {
  it("matches every positive sample to exactly the codes in expected.json", () => {
    const expected = JSON.parse(readFileSync(join(positiveDir, "expected.json"), "utf8")) as Record<string, string[]>;
    const files = readdirSync(positiveDir).filter((name) => name.endsWith(".lua")).sort();
    expect(Object.keys(expected).sort()).toEqual(files);
    for (const name of files) {
      const result = securityRules(name, readFileSync(join(positiveDir, name), "utf8"));
      expect(result.parsed, name).toBe(true);
      expect(result.findings.map((f) => f.code).sort(), name).toEqual([...expected[name]].sort());
    }
  });

  it("reports no findings for negative samples", () => {
    const files = readdirSync(negativeDir).filter((name) => name.endsWith(".lua")).sort();
    expect(files.length).toBeGreaterThan(0);
    for (const name of files) {
      const result = securityRules(name, readFileSync(join(negativeDir, name), "utf8"));
      expect(result.parsed, name).toBe(true);
      expect(result.findings, name).toEqual([]);
    }
  });
});
