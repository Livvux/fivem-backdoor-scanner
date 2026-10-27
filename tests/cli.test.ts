import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { strToU8, zipSync } from "fflate";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/run-cli.js";

const dirs: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "fivem-scan-"));
  dirs.push(dir);
  return dir;
}

describe("cli", () => {
  it("exits 0 when nothing matches", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "server.lua"), "print('hi')\n");
    vi.spyOn(console, "log").mockImplementation(() => {});
    expect(await main([dir])).toBe(0);
  });

  it("exits 1 for a warning and 2 for hidden code", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "server.lua"), "local key = GetConvar('sv_licenseKey', '')\n");
    vi.spyOn(console, "log").mockImplementation(() => {});
    expect(await main([dir])).toBe(1);

    writeFileSync(join(dir, "client.lua"), `${" ".repeat(450)}load(x)\n`);
    expect(await main([dir, "--json"])).toBe(2);
  });

  it("skips node_modules, .git and stream", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "server.lua"), "print(1)\n");
    for (const skip of ["node_modules", ".git", "stream"]) {
      const nested = join(dir, skip);
      mkdirSync(nested);
      writeFileSync(join(nested, "bad.lua"), "os.execute('x')\n");
    }
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line?: unknown) => {
      logs.push(String(line));
    });
    expect(await main([dir, "--json"])).toBe(0);
    const report = JSON.parse(logs.at(-1) ?? "{}") as { findings: unknown[]; scanned: number };
    expect(report.findings).toEqual([]);
    expect(report.scanned).toBe(1);
  });

  it("exits 3 when the path is missing, the ZIP is not a ZIP, or the option is unknown", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await main([])).toBe(3);
    expect(await main(["--nope", "x"])).toBe(3);
    expect(await main([join(tempDir(), "missing")])).toBe(3);
    const zip = join(tempDir(), "bad.zip");
    writeFileSync(zip, "not a zip");
    expect(await main([zip])).toBe(3);
  });

  it("scans a ZIP and prints JSON", async () => {
    const dir = tempDir();
    const file = join(dir, "pack.zip");
    writeFileSync(file, zipSync({ "server.lua": strToU8("os.execute('x')") }));
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line?: unknown) => {
      logs.push(String(line));
    });
    expect(await main([file, "--json"])).toBe(1);
    const report = JSON.parse(logs.at(-1) ?? "{}") as { findings: { code: string }[] };
    expect(report.findings.map((f) => f.code)).toContain("LAB-SEC-106");
  });
});

describe.skipIf(!existsSync(new URL("../dist/run-cli.js", import.meta.url)))("cli bin", () => {
  it("runs node cli/index.js after a build", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "server.lua"), "print('hi')\n");
    const res = spawnSync(process.execPath, ["cli/index.js", dir, "--json"], { encoding: "utf8" });
    expect(res.status).toBe(0);
    expect(JSON.parse(res.stdout).verdict).toBe("clean");
  });
});
