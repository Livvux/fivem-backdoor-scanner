
// The backdoor scanner's limits and file selection, without the checks.
import type { Finding } from "./findings.js";

export const MAX_SCAN_ZIP = 300 * 1024 * 1024;
export const MAX_FILE = 2 * 1024 * 1024;
const MAX_TEXT = 120 * 1024 * 1024;
const SCANNED = /\.(?:lua|js)$/i;

/**
 * hidden: hidden code found. suspicious: other findings. partial: nothing found in what was read, but something was not
 * analysed (or nothing at all). clean: every Lua file was analysed in full and nothing was found. Findings always win
 * over coverage: a partial scan with a finding is still hidden/suspicious, and its limits are shown next to it.
 */
export type ScanVerdict = "hidden" | "suspicious" | "partial" | "clean";

export type ScanReport = {
  verdict: ScanVerdict;
  /** Lua files every check ran on. */
  scanned: number;
  /** Files in the lists below (escrow folders not counted): read only in part or not at all. */
  notAnalyzed: number;
  findings: Finding[];
  /** Lua that didn't parse: only the hidden-code check ran on it. */
  unparsed: string[];
  /** JavaScript: only the hidden-code check ran on it (the backdoor rules are Lua rules). */
  javascript: string[];
  /** Compiled Lua, or entries that couldn't be read as the archive declares them (corrupt, encrypted, duplicated path). */
  unreadable: string[];
  /** Over the size limits: not read. */
  skipped: string[];
  /** Folders with escrow-encrypted (.fxap) files: their protected code can't be read by anyone but FXServer. */
  escrowed: string[];
  /** Archives inside the upload: not unpacked. */
  archives: string[];
};

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
// Lua reads source as bytes: Latin-1 maps every byte to one character, so nothing is dropped from the checks.
const latin1 = new TextDecoder("latin1");
/** File bytes as the checks see them, the same for ZIP entries and picked files. */
export function decodeSource(bytes: Uint8Array): string {
  try {
    return utf8.decode(bytes);
  } catch {
    return latin1.decode(bytes);
  }
}

/** The limits a report lists. */
export const LIMITS = ["escrowed", "unreadable", "javascript", "unparsed", "skipped", "archives"] as const;

export function verdictOf(r: Omit<ScanReport, "verdict" | "notAnalyzed">): ScanVerdict {
  if (r.findings.some((f) => f.severity === "error")) return "hidden";
  if (r.findings.length) return "suspicious";
  return r.scanned === 0 || LIMITS.some((k) => r[k].length) ? "partial" : "clean";
}

// Directories only. macOS metadata (`._x`, `__MACOSX/`) is recognised by its content, not its name (scan.ts).
export const ignored = (name: string) => name.endsWith("/");

/** Which entries to read: Lua/JS within the size limits. Shared by ZIP uploads and folder picks. */
export function plan(entries: { name: string; size: number }[]): { wanted: Set<string>; skipped: string[] } {
  const skipped: string[] = [];
  let total = 0;
  const wanted = entries
    .filter((e) => !ignored(e.name) && SCANNED.test(e.name))
    .filter((e) => {
      total += e.size;
      if (e.size <= MAX_FILE && total <= MAX_TEXT) return true;
      skipped.push(e.name);
      return false;
    })
    .map((e) => e.name);
  return { wanted: new Set(wanted), skipped };
}


