
// Backdoor checks over every Lua and JavaScript file in an upload (one resource, a category folder or a whole server).
// Only the per-file security checks run; archive-level checks look at entry names.
import { archiveRisks } from "./archive-risks.js";
import { type Finding, finding, sortFindings } from "./findings.js";
import { securityRules } from "./rules.js";
import { decodeSource, ignored, MAX_FILE, MAX_SCAN_ZIP, plan, type ScanReport, verdictOf } from "./scan-plan.js";
import { bufferRange, readZipEntries, readZipIndex } from "./zip-index.js";

export type { ScanReport };

// macOS metadata (AppleDouble, magic 0x00051607): what `._x` files under `__MACOSX/` really are. Lua can't load it
// (the first byte is NUL), so it is skipped; anything else with such a name is scanned like every other file.
const isAppleDouble = (source: string) => source.startsWith("\0\x05\x16\x07");
// Names only: macOS metadata (`__MACOSX/…/._x.zip`) isn't a nested archive (the content check above is for code).
const metadataName = (name: string) => name.startsWith("__MACOSX/") && name.split("/").at(-1)!.startsWith("._");

const folderOf = (name: string) => name.slice(0, name.lastIndexOf("/") + 1) || "./";
const list = (names: string[]) => names.slice(0, 5).join(", ") + (names.length > 5 ? ", …" : "");

type Extra = Partial<Omit<ScanReport, "verdict" | "notAnalyzed" | "scanned" | "unparsed" | "javascript">>;

export function scanFiles(files: Record<string, string>, extra: Extra = {}): ScanReport {
  const findings: Finding[] = [];
  const unparsed: string[] = [];
  const javascript: string[] = [];
  const unreadable = [...(extra.unreadable ?? [])];
  let scanned = 0;
  for (const [path, source] of Object.entries(files).sort(([a], [b]) => a.localeCompare(b))) {
    if (isAppleDouble(source)) continue;
    if (source.startsWith("\x1bLua")) {
      unreadable.push(path);
      continue;
    }
    const result = securityRules(path, source);
    findings.push(...result.findings);
    if (!path.toLowerCase().endsWith(".lua")) javascript.push(path);
    else if (!result.parsed) unparsed.push(path);
    else scanned++;
  }
  const base = { skipped: [], escrowed: [], archives: [], ...extra, scanned, findings: sortFindings([...findings, ...(extra.findings ?? [])]), unparsed, javascript, unreadable: [...new Set(unreadable)].sort() };
  const notAnalyzed = base.unparsed.length + base.javascript.length + base.unreadable.length + base.skipped.length + base.archives.length;
  return { ...base, verdict: verdictOf(base), notAnalyzed };
}

/** The archive-level checks (names only) plus the per-file checks. `names`: every entry, also the ones not read. */
export function scanEntries(names: string[], files: Record<string, string>, extra: Pick<ScanReport, "unreadable" | "skipped">): ScanReport {
  const kept = names.filter((n) => !ignored(n));
  const { executables, unsafePaths } = archiveRisks(kept);
  return scanFiles(files, {
    ...extra,
    escrowed: [...new Set(kept.filter((n) => n.toLowerCase().endsWith(".fxap")).map(folderOf))],
    archives: kept.filter((n) => !metadataName(n) && /\.(?:zip|rar|7z)$/i.test(n)),
    findings: [
      ...(executables.length ? [finding("LAB-PKG-004", `${executables.length} executable or system script file(s): ${list(executables)}`)] : []),
      ...(unsafePaths.length ? [finding("LAB-PKG-005", `${unsafePaths.length} path(s) that escape the extraction folder: ${list(unsafePaths)}`)] : []),
    ],
  });
}

/**
 * A ZIP upload, read through the strict reader (zip-index.ts): an entry whose bytes don't match what the archive
 * declares (size, CRC, local header, a second entry with the same path) is unreadable, never a truncated clean file.
 */
export async function scanZip(zip: Uint8Array): Promise<ScanReport> {
  if (zip.length > MAX_SCAN_ZIP) throw new Error("too_large");
  const read = bufferRange(zip);
  let index;
  try {
    index = (await readZipIndex(zip.length, read, { contiguous: true })).filter((e) => !ignored(e.name));
  } catch {
    throw new Error("invalid_zip");
  }
  const { wanted, skipped } = plan(index.map((e) => ({ name: e.name, size: e.size })));
  const raw = await readZipEntries(index.filter((e) => wanted.has(e.name)), zip.length, read, { maxEntry: MAX_FILE, all: index });
  const files: Record<string, string> = {};
  for (const [name, data] of Object.entries(raw)) files[name] = decodeSource(data);
  // Wanted entries the reader left out, and any entry an extractor would write under another name (whatever its extension).
  const unreadable = [...[...wanted].filter((n) => !(n in raw)), ...index.filter((e) => e.aliased).map((e) => e.name)];
  return scanEntries(index.map((e) => e.name), files, { unreadable, skipped });
}


