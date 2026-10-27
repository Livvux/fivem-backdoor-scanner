import { describe, expect, it } from "vitest";
import { securityRules } from "../src/index.js";

describe("LAB-SEC-107 performance", () => {
  it("finishes a 500 KB line of blanks in under 100 ms", () => {
    const source = `print('ok')${" ".repeat(500_000)}`;
    const start = performance.now();
    const result = securityRules("server.lua", source);
    expect(performance.now() - start).toBeLessThan(100);
    expect(result.findings).toEqual([]);
    expect(result.parsed).toBe(true);
  });
});
