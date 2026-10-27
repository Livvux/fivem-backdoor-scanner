# Ruleset changelog

Versions are `YYYY.MM.N`. A rule code never changes meaning.

## 2026.10.6

- LAB-SEC-101 … LAB-SEC-107, LAB-PKG-004, LAB-PKG-005 as used by
  https://rpscripts.net/tools/fivem-backdoor-scanner/
- LAB-SEC-107 treats space, tab, vertical tab and form feed as blanks and runs in
  linear time on very long lines.
- LAB-PKG-004 also matches `.dll` and `.cmd`. `.dll` files are not flagged when the
  package contains a `*.net.dll` (a C# resource).
