import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { RULES, RULESET_VERSION } from "../src/index.js";

const PUBLISHED = ["LAB-PKG-004", "LAB-PKG-005", "LAB-SEC-101", "LAB-SEC-102", "LAB-SEC-103", "LAB-SEC-104", "LAB-SEC-105", "LAB-SEC-106", "LAB-SEC-107"];

describe("rules catalog", () => {
  it("is the only source of RULES and contains just the public backdoor codes", () => {
    const catalog = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../rules/catalog.json"), "utf8")) as {
      rulesetVersion: string;
      rules: Record<string, { title: string }>;
    };
    expect(RULESET_VERSION).toBe(catalog.rulesetVersion);
    expect(RULESET_VERSION).toBe("2026.10.6");
    expect(Object.keys(RULES).sort()).toEqual(PUBLISHED);
    expect(Object.keys(catalog.rules).sort()).toEqual(PUBLISHED);
    for (const code of PUBLISHED) expect(RULES[code]?.title).toBe(catalog.rules[code]?.title);
  });
});
