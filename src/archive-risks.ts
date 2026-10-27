// Archive entry names: executables a resource does not need, and paths that escape the extraction folder.
// Names only; nothing is inflated or executed.

const EXECUTABLE = /\.(?:exe|dll|bat|cmd|ps1|sh|vbs|jar|scr)$/i;
/** `..` segments, absolute paths, backslashes or drive letters: extracting these can write outside the target folder. */
const UNSAFE_PATH = (n: string) => n.startsWith("/") || n.includes("\\") || /^[a-z]:/i.test(n) || n.split("/").includes("..");

/** Archive entries no resource needs (executables) or that escape the folder (unsafe paths). Names only, nothing inflated. */
export function archiveRisks(names: string[]): { executables: string[]; unsafePaths: string[] } {
  const all = names.filter((n) => !n.endsWith("/"));
  // macOS metadata (`__MACOSX/…/._x.exe` next to a real x.exe) is not an executable of its own; a path escape is one
  // wherever it is (`__MACOSX/../../x` writes outside the folder too).
  const entries = all.filter((n) => !(n.startsWith("__MACOSX/") && n.split("/").at(-1)!.startsWith("._")));
  // C# resources ship their assemblies (*.net.dll plus referenced .dll files); FXServer loads them, so they're expected there.
  const csharp = entries.some((n) => /\.net\.dll$/i.test(n));
  return {
    executables: entries.filter((n) => EXECUTABLE.test(n) && !(csharp && /\.dll$/i.test(n))),
    unsafePaths: all.filter(UNSAFE_PATH),
  };
}
