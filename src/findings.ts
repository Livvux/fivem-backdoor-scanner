// Structured findings with stable codes. Codes never change meaning; retired rules keep their code unused.
// "confirmed" = the platform or a pinned upstream source says so; "likely" = a pattern that is almost always a bug;
// "heuristic" = worth a look, can be fine (e.g. the value is validated somewhere we can't see).
//
// Rule texts are loaded from rules/catalog.json (the published source of truth). This package only ships the
// backdoor rules: LAB-SEC-1xx and LAB-PKG-004/005.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export type Severity = "error" | "warning" | "info";
export type Confidence = "confirmed" | "likely" | "heuristic";
export type Method = "syntax" | "manifest" | "framework-api" | "natives" | "pattern" | "package" | "luals" | "runtime" | "log";
export type Ref = { label: string; url: string };

export type Finding = {
  code: string;
  severity: Severity;
  confidence: Confidence;
  method: Method;
  title: string;
  message: string;
  fix: string;
  path?: string;
  line?: number;
  column?: number;
  refs: Ref[];
  ruleVersion: string;
};

type Rule = Pick<Finding, "severity" | "confidence" | "method" | "title" | "fix"> & { refs: Ref[] };

const SEVERITIES = new Set<Severity>(["error", "warning", "info"]);
const CONFIDENCE = new Set<Confidence>(["confirmed", "likely", "heuristic"]);
const METHODS = new Set<Method>(["syntax", "manifest", "framework-api", "natives", "pattern", "package", "luals", "runtime", "log"]);

type Catalog = {
  rulesetVersion?: unknown;
  rules?: Record<string, Partial<Rule> | undefined>;
};

function loadCatalog(): { rulesetVersion: string; rules: Record<string, Rule> } {
  const file = fileURLToPath(new URL("../rules/catalog.json", import.meta.url));
  const catalog = JSON.parse(readFileSync(file, "utf8")) as Catalog;
  if (typeof catalog.rulesetVersion !== "string" || catalog.rulesetVersion === "" || !catalog.rules) {
    throw new Error("rules/catalog.json is missing rulesetVersion or rules");
  }
  const rules: Record<string, Rule> = {};
  for (const [code, rule] of Object.entries(catalog.rules)) {
    if (
      !rule ||
      !SEVERITIES.has(rule.severity as Severity) ||
      !CONFIDENCE.has(rule.confidence as Confidence) ||
      !METHODS.has(rule.method as Method) ||
      typeof rule.title !== "string" ||
      typeof rule.fix !== "string" ||
      !Array.isArray(rule.refs)
    ) {
      throw new Error(`rules/catalog.json rule ${code} is incomplete or has an unknown field`);
    }
    rules[code] = {
      severity: rule.severity as Severity,
      confidence: rule.confidence as Confidence,
      method: rule.method as Method,
      title: rule.title,
      fix: rule.fix,
      refs: rule.refs,
    };
  }
  return { rulesetVersion: catalog.rulesetVersion, rules };
}

const catalog = loadCatalog();

export const RULESET_VERSION = catalog.rulesetVersion;

export const RULES: Record<string, Rule> = catalog.rules;

export type RuleCode = keyof typeof RULES;

export function finding(code: RuleCode, message: string, at: { path?: string; line?: number; column?: number } = {}, extraRefs: Ref[] = []): Finding {
  const rule = RULES[code];
  if (!rule) throw new Error(`unknown rule ${code}`);
  return { code, ...rule, message, ...at, refs: [...rule.refs, ...extraRefs], ruleVersion: RULESET_VERSION };
}

const ORDER: Record<Severity, number> = { error: 0, warning: 1, info: 2 };
export const sortFindings = (list: Finding[]) =>
  [...list].sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || (a.path ?? "").localeCompare(b.path ?? "") || (a.line ?? 0) - (b.line ?? 0));
