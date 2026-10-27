import { describe, expect, it } from "vitest";
import { archiveRisks } from "../src/index.js";

describe("archive entry names", () => {
  it("finds executables and unsafe paths; C# assemblies are expected", () => {
    expect(archiveRisks(["r/fxmanifest.lua", "r/setup.EXE", "r/run.bat", "r/tools/fix.ps1", "__MACOSX/r/._x.sh", "r/ui/app.js"])).toEqual({
      executables: ["r/setup.EXE", "r/run.bat", "r/tools/fix.ps1"],
      unsafePaths: [],
    });
    expect(archiveRisks(["r/Game.Client.net.dll", "r/Newtonsoft.Json.dll"]).executables).toEqual([]);
    expect(archiveRisks(["r/helper.dll"]).executables).toEqual(["r/helper.dll"]);
    expect(archiveRisks(["../evil.lua", "r/../../x.lua", "/etc/passwd", "C:/x.lua", "r\\..\\x.lua", "r/ok..lua"]).unsafePaths).toEqual([
      "../evil.lua",
      "r/../../x.lua",
      "/etc/passwd",
      "C:/x.lua",
      "r\\..\\x.lua",
    ]);
  });
});
