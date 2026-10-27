
import type { Chunk, Expression, Node } from "luaparse";
import { parse } from "luaparse";

type Span = { kind: "code" | "string" | "hash" | "comment" | "ccomment"; text: string };

const longBracket = (src: string, i: number) => /^\[(=*)\[/.exec(src.slice(i, i + 64));

/** Splits Lua source into code, strings ('…', "…", [[…]]), backtick hashes, comments and CfxLua's C-style comments. */
export function luaSpans(src: string): Span[] {
  const spans: Span[] = [];
  let start = 0;
  let i = 0;
  const push = (kind: Span["kind"], end: number) => {
    if (start < i) spans.push({ kind: "code", text: src.slice(start, i) });
    spans.push({ kind, text: src.slice(i, end) });
    i = start = end;
  };
  const closeLong = (from: number, eq: string) => {
    const end = src.indexOf(`]${eq}]`, from);
    return end < 0 ? src.length : end + eq.length + 2;
  };
  while (i < src.length) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "*") {
      // CfxLua also accepts C-style block comments
      const end = src.indexOf("*/", i + 2);
      push("ccomment", end < 0 ? src.length : end + 2);
    } else if (c === "-" && src[i + 1] === "-") {
      const long = longBracket(src, i + 2);
      push("comment", long ? closeLong(i + 2 + long[0].length, long[1]) : (src.indexOf("\n", i) + 1 || src.length));
    } else if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      push(c === "`" ? "hash" : "string", Math.min(j + 1, src.length));
    } else if (c === "[" && longBracket(src, i)) {
      const long = longBracket(src, i) as RegExpExecArray;
      push("string", closeLong(i + long[0].length, long[1]));
    } else i++;
  }
  if (start < src.length) spans.push({ kind: "code", text: src.slice(start) });
  return spans;
}

// FiveM's CfxLua accepts syntax luaparse (Lua 5.3) doesn't: 5.4 attribs, compound assignment (`x += 1`), safe
// navigation (`a?.b`, `a?[k]`, `a?:m()`), backtick hashes (`adder`) and /* */ comments. Rewrite them in code only (never inside
// strings or comments) into plain Lua of the same length, so line/column numbers stay right.
const ATTRIB = /<\s*(?:const|close)\s*>/g;
const COMPOUND = /(?:\/\/|<<|>>|\.\.|[-+*/%^&|])=(?!=)/g;
const SAFE_NAV = /\?(?=[.[:])/g;
export const toPlainLua = (source: string) =>
  luaSpans(source)
    .map((s) =>
      s.kind === "hash"
        ? s.text.length > 1 && s.text.endsWith("`")
          ? `"${s.text.slice(1, -1)}"`
          : s.text // unterminated: left as is, the parser reports it
        : s.kind === "ccomment"
          ? s.text.replace(/[^\n]/g, " ")
        : s.kind !== "code"
          ? s.text
          : s.text
              .replace(ATTRIB, (m) => " ".repeat(m.length))
              .replace(COMPOUND, (m) => `${" ".repeat(m.length - 1)}=`)
              .replace(SAFE_NAV, " "),
    )
    .join("");

/** For LuaLS, which reads CfxLua's other extensions itself (nonstandardSymbol) but not safe navigation. */
export const toLuaLS = (source: string) =>
  luaSpans(source)
    .map((s) => (s.kind === "code" ? s.text.replace(SAFE_NAV, " ") : s.text))
    .join("");

export const parseLua = (source: string, locations = false): Chunk => parse(toPlainLua(source), { luaVersion: "5.3", locations });

/** `a.b.c` / `a.b:c` → ["a", "b", "c"]; null when any part isn't a plain identifier (e.g. `a[1].b`). */
export function memberPath(e: Expression): string[] | null {
  if (e.type === "Identifier") return [e.name];
  if (e.type !== "MemberExpression") return null;
  const base = memberPath(e.base);
  return base && [...base, e.identifier.name];
}

const isNode = (v: unknown): v is Node => typeof v === "object" && v !== null && typeof (v as { type?: unknown }).type === "string";

/** Depth-first over every node; `visit` gets the node and its parent. */
export function walk(node: Node, visit: (n: Node, parent: Node | null) => void, parent: Node | null = null): void {
  visit(node, parent);
  for (const [key, value] of Object.entries(node)) {
    if (key === "loc" || key === "range") continue;
    if (Array.isArray(value)) {
      for (const v of value) if (isNode(v)) walk(v, visit, node);
    } else if (isNode(value)) walk(value, visit, node);
  }
}

/** String literal content. luaparse only fills `value` in encoding modes that reject non-Latin-1 text, so read raw. */
export const stringValue = (raw: string) => (/^['"]/.test(raw) ? raw.slice(1, -1) : raw.replace(/^\[=*\[\n?|\]=*\]$/g, ""));


