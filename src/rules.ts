// Static checks for known FiveM/RedM backdoor shapes. Nothing here is executed.
// Heuristics point at code worth reading (remote loaders, obfuscation, secret readers, shell access).
// They are not proof of malice. LAB-SEC-107 is reported as an error; the others are warnings.
// Thresholds are set so the maintained corpus stays clean.
import type { Expression, Node } from "luaparse";
import { type Finding, finding } from "./findings.js";
import { memberPath, parseLua, stringValue, walk } from "./lua-ast.js";

type Call = Extract<Node, { type: "CallExpression" | "StringCallExpression" | "TableCallExpression" }>;
type Parsed = { path: string; chunk: Node };

const isCall = (n: Node): n is Call => n.type === "CallExpression" || n.type === "StringCallExpression" || n.type === "TableCallExpression";
const argsOf = (c: Call): Expression[] => (c.type === "CallExpression" ? c.arguments : c.type === "StringCallExpression" ? [c.argument] : [c.arguments]);
/** `Citizen.Wait`, `Player.Functions.AddMoney`, `xPlayer:addMoney` → dotted path; null for computed callees. */
const calleeOf = (c: Call): string | null => memberPath(c.base)?.join(".") ?? null;
const lastOf = (name: string) => name.slice(name.lastIndexOf(".") + 1);
const literal = (e: Expression | undefined) => (e?.type === "StringLiteral" ? stringValue(e.raw) : null);
const lineOf = (n: Node) => n.loc?.start.line;

/** Every call in a subtree, with the callee name. */
function calls(root: Node): { call: Call; name: string | null }[] {
  const out: { call: Call; name: string | null }[] = [];
  walk(root, (n) => {
    if (isCall(n)) out.push({ call: n, name: calleeOf(n) });
  });
  return out;
}

const ESCAPE = /\\(?:x[0-9a-fA-F]{2}|\d{1,3})/g;
/** Escaped bytes in one literal from which it counts as hidden text (a few \n-style escapes are normal). */
const MIN_ESCAPES = 40;
/** base64 or hex without spaces, this long, is data or code, not text. */
const BLOB = /^(?:[A-Za-z0-9+/]{400,}={0,2}|[0-9a-fA-F]{400,})$/;
/** string.char(…) with this many arguments spells out text byte by byte. */
const MIN_CHAR_ARGS = 20;
const DECODER = /(?:decode|unhex|fromhex|base64|b64|deobf)/i;
const SECRET = /^(?:sv_licenseKey|rcon_password|sv_tebexSecret)$/i;
const DB_SECRET = /^mysql_connection_string$/i;
/** http(s) URL to a public IPv4 address (loopback and private ranges are local services). */
const IP_URL = /^(?:https?:)?\/\/(?!(?:127|10|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}(?:\.\d{1,3}){3}(?:[:/?]|$)/i;
const HTTP = new Set(["PerformHttpRequest", "PerformHttpRequestAwait"]);
const LOADERS = new Set(["load", "loadstring"]);

const escapes = (raw: string) => raw.match(ESCAPE)?.length ?? 0;

/** Text decoded at runtime: string.char, decoder functions or literals written as escaped bytes. */
function hidden(e: Node): boolean {
  let found = false;
  walk(e, (n) => {
    if (found) return;
    if (n.type === "StringLiteral" && escapes(n.raw) >= 8) found = true;
    if (isCall(n)) {
      const name = calleeOf(n);
      if (name === "string.char" || (name && DECODER.test(lastOf(name)))) found = true;
    }
  });
  return found;
}

// Code pushed far past the right edge by a long run of spaces: how a known FiveM backdoor family hides its loader
// (`<7,168 spaces>vdwa=…local a=load(…)` appended to a normal line). A comment after the gap is no code.
// Each run is taken whole from its first blank (atomic via lookahead + backreference): `[ \t]{400,}` alone backtracks
// quadratically on a long run without code after it (a 500 KB run of spaces must stay cheap).
// Blanks are Lua's in-line whitespace: space, tab, vertical tab, form feed.
const HIDDEN_CODE = /(?<![ \t\v\f])(?=([ \t\v\f]{400,}))\1(?!--|\/\/|\/\*)\S/;

function hiddenCode(files: Record<string, string>, paths: string[]): Finding[] {
  return paths.flatMap((path) => {
    const m = HIDDEN_CODE.exec(files[path]);
    if (!m) return [];
    const line = files[path].slice(0, m.index).split("\n").length;
    return [finding("LAB-SEC-107", "Code continues after a long run of spaces, out of view in any editor.", { path, line })];
  });
}

/**
 * The backdoor checks alone, one file at a time.
 * Hidden code is looked for in any text file; the Lua checks need a parse. `parsed: false`: the Lua checks could not run.
 */
export function securityRules(path: string, source: string): { findings: Finding[]; parsed: boolean } {
  const hiddenFindings = hiddenCode({ [path]: source }, [path]);
  if (!path.toLowerCase().endsWith(".lua")) return { findings: hiddenFindings, parsed: true };
  try {
    return { findings: [...suspiciousRules([{ path, chunk: parseLua(source, true) as Node }]), ...hiddenFindings], parsed: true };
  } catch {
    return { findings: hiddenFindings, parsed: false };
  }
}

function suspiciousRules(all: Parsed[]): Finding[] {
  const out: Finding[] = [];
  for (const p of all) {
    const list = calls(p.chunk);
    const http = list.filter(({ name }) => name && HTTP.has(name));
    const remote = new Set<Node>();
    // io.popen('ls "…"') / ('dir "…" /b') to list a folder is common (ox_doorlock, ox_lib-style loaders).
    let lists = false;
    walk(p.chunk, (n) => {
      if (n.type === "StringLiteral" && /^(?:ls|dir)(?:\s|$)/.test(stringValue(n.raw))) lists = true;
    });

    // Code loaded inside an HTTP response handler: the classic `PerformHttpRequest(url, function(_, body) assert(load(body))() end)`.
    for (const { call } of http)
      for (const fn of argsOf(call).filter((a) => a.type === "FunctionDeclaration"))
        for (const inner of calls(fn))
          if (inner.name && LOADERS.has(inner.name)) {
            remote.add(inner.call);
            out.push(finding("LAB-SEC-101", `${inner.name}() runs the body of an HTTP response: whoever controls that server can run any code on yours.`, { path: p.path, line: lineOf(inner.call) }));
          }

    for (const { call, name } of list) {
      if (!name) continue;
      const args = argsOf(call);
      if (LOADERS.has(name) && !remote.has(call) && args[0] && hidden(args[0]))
        out.push(finding("LAB-SEC-102", `${name}() runs text that is only decoded at runtime.`, { path: p.path, line: lineOf(call) }));
      if ((name === "GetConvar" || name === "GetConvarInt") && args[0]) {
        const convar = literal(args[0]);
        if (convar && (SECRET.test(convar) || (DB_SECRET.test(convar) && http.length > 0)))
          out.push(finding("LAB-SEC-104", `Reads the convar '${convar}'${http.length ? " in a file that also sends HTTP requests" : ""}.`, { path: p.path, line: lineOf(call) }));
      }
      if (HTTP.has(name) && args[0] && hidden(args[0]))
        out.push(finding("LAB-SEC-105", "The address of this HTTP request is only decoded at runtime.", { path: p.path, line: lineOf(call) }));
      if (name === "os.execute" || (name === "io.popen" && !lists))
        out.push(finding("LAB-SEC-106", `${name} runs a program on the server's host.`, { path: p.path, line: lineOf(call) }));
      if (name === "io.open" && /^[wa]|\+/.test(literal(args[1]) ?? "") && !JSON.stringify(args[0] ?? null).includes("GetResourcePath"))
        out.push(finding("LAB-SEC-106", "io.open writes to a path that isn't built from GetResourcePath(…).", { path: p.path, line: lineOf(call) }));
    }

    // SaveResourceFile into a resource computed at runtime (e.g. every resource from GetResourceByFindIndex) — how
    // backdoors spread. A literal name is explicit (ox_doorlock writes to 'ox_doorlock') and not reported.
    const own = new Set<string>();
    walk(p.chunk, (n) => {
      if (n.type === "LocalStatement" || n.type === "AssignmentStatement")
        n.init.forEach((e, i) => {
          const v = n.variables[i];
          if (v?.type === "Identifier" && isCall(e) && calleeOf(e) === "GetCurrentResourceName") own.add(v.name);
        });
    });
    for (const { call, name } of list) {
      if (name !== "SaveResourceFile") continue;
      const target = argsOf(call)[0];
      const mine =
        !target ||
        (isCall(target) && calleeOf(target) === "GetCurrentResourceName") ||
        (target.type === "Identifier" && own.has(target.name)) ||
        literal(target) !== null;
      if (!mine) out.push(finding("LAB-SEC-106", "SaveResourceFile writes into a resource that may not be this one.", { path: p.path, line: lineOf(call) }));
    }

    // Obfuscated data and raw-IP addresses: one finding per file, at the first occurrence.
    const first: { blob?: { line?: number; what: string }; ip?: { line?: number; url: string } } = {};
    walk(p.chunk, (n) => {
      if (n.type === "StringLiteral") {
        const value = stringValue(n.raw);
        const count = escapes(n.raw);
        if (count >= MIN_ESCAPES) first.blob ??= { line: lineOf(n), what: `a string of ${count} escaped bytes` };
        if (BLOB.test(value)) first.blob ??= { line: lineOf(n), what: `a ${value.length}-character base64/hex string` };
        if (http.length && IP_URL.test(value)) first.ip ??= { line: lineOf(n), url: value.slice(0, 60) };
      }
      if (isCall(n) && calleeOf(n) === "string.char" && argsOf(n).length >= MIN_CHAR_ARGS) first.blob ??= { line: lineOf(n), what: `string.char with ${argsOf(n).length} bytes` };
    });
    if (first.blob) out.push(finding("LAB-SEC-103", `This file contains ${first.blob.what}.`, { path: p.path, line: first.blob.line }));
    if (first.ip) out.push(finding("LAB-SEC-105", `A file that sends HTTP requests contains the raw-IP address '${first.ip.url}'.`, { path: p.path, line: first.ip.line }));
  }
  return out;
}
