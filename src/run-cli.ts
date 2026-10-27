import { readdirSync, readFileSync, statSync, type Dirent } from "node:fs";
import { basename, join, relative, sep } from "node:path";
import { scanEntries, scanFiles, scanZip } from "./scan.js";
import { decodeSource, MAX_SCAN_ZIP, plan, type ScanReport } from "./scan-plan.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "stream"]);

export const USAGE = `fivem-backdoor-scan <folder-or-zip> [--json]

Scan a FiveM resource folder or a ZIP for known backdoor patterns.
JavaScript is checked for hidden code only. Folders skip node_modules, .git and stream.
Exit codes: 0 no finding, 1 warnings only, 2 at least one error, 3 the scan could not run.`;

/** 0 no finding, 1 warnings only, 2 at least one finding with severity error. */
export function exitCode(report: ScanReport): 0 | 1 | 2 {
  if (report.findings.some((f) => f.severity === "error")) return 2;
  if (report.findings.length > 0) return 1;
  return 0;
}

function walk(root: string): { name: string; full: string; size: number }[] {
  const out: { name: string; full: string; size: number }[] = [];
  const visit = (dir: string) => {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      throw new Error(`cannot read ${dir}: ${e instanceof Error ? e.message : e}`);
    }
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue;
      const full = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        visit(full);
        continue;
      }
      if (!ent.isFile()) continue;
      const name = relative(root, full).split(sep).join("/");
      out.push({ name, full, size: statSync(full).size });
    }
  };
  visit(root);
  return out;
}

function scanFolder(root: string): ScanReport {
  const entries = walk(root);
  const { wanted, skipped } = plan(entries.map((e) => ({ name: e.name, size: e.size })));
  const files: Record<string, string> = {};
  const unreadable: string[] = [];
  for (const entry of entries) {
    if (!wanted.has(entry.name)) continue;
    try {
      files[entry.name] = decodeSource(new Uint8Array(readFileSync(entry.full)));
    } catch {
      unreadable.push(entry.name);
    }
  }
  return scanEntries(
    entries.map((e) => e.name),
    files,
    { unreadable, skipped },
  );
}

async function scanPath(target: string): Promise<ScanReport> {
  let st;
  try {
    st = statSync(target);
  } catch {
    throw new Error(`cannot read ${target}`);
  }
  if (st.isDirectory()) return scanFolder(target);
  if (!st.isFile()) throw new Error(`cannot read ${target}`);
  if (target.toLowerCase().endsWith(".zip")) {
    if (st.size > MAX_SCAN_ZIP) throw new Error("too_large");
    return scanZip(new Uint8Array(readFileSync(target)));
  }
  return scanFiles({ [basename(target)]: decodeSource(new Uint8Array(readFileSync(target))) });
}

function printHuman(report: ScanReport): void {
  console.log(`verdict: ${report.verdict}`);
  console.log(`scanned: ${report.scanned}`);
  if (report.notAnalyzed) console.log(`not analyzed: ${report.notAnalyzed}`);
  const limits: [string, string[]][] = [
    ["unparsed", report.unparsed],
    ["javascript", report.javascript],
    ["unreadable", report.unreadable],
    ["skipped", report.skipped],
    ["escrowed", report.escrowed],
    ["archives", report.archives],
  ];
  for (const [name, items] of limits) {
    if (items.length) console.log(`${name}: ${items.join(", ")}`);
  }
  if (!report.findings.length) {
    console.log("no findings");
    return;
  }
  console.log("");
  for (const f of report.findings) {
    const at = f.path ? `${f.path}${f.line ? `:${f.line}` : ""}` : "";
    console.log(`${f.code}\t${f.severity}\t${at}\t${f.title}`);
    console.log(`  ${f.message}`);
  }
}

function failureText(message: string): string {
  if (message === "too_large") return "ZIP is larger than 300 MB";
  if (message === "invalid_zip") return "not a valid ZIP";
  return message;
}

export async function main(argv: string[]): Promise<number> {
  let json = false;
  const paths: string[] = [];
  for (const arg of argv) {
    if (arg === "--json") json = true;
    else if (arg === "--help" || arg === "-h") {
      console.log(USAGE);
      return 0;
    } else if (arg.startsWith("-")) {
      console.error(`Unknown option: ${arg}`);
      console.error(USAGE);
      return 3;
    } else paths.push(arg);
  }
  if (paths.length !== 1) {
    console.error(USAGE);
    return 3;
  }
  try {
    const report = await scanPath(paths[0]);
    if (json) console.log(JSON.stringify(report, null, 2));
    else printHuman(report);
    return exitCode(report);
  } catch (e) {
    console.error(failureText(e instanceof Error ? e.message : String(e)));
    return 3;
  }
}
