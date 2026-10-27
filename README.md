# FiveM Backdoor Scanner — rules and test corpus

Static checks that flag the code patterns known FiveM/RedM backdoors use: Lua that
runs code downloaded over HTTP, code hidden behind a long run of spaces, obfuscated
loaders, resources that read server secrets, raw-IP callbacks, shell access, and
archive entries that escape their folder.

These are the same rules that run in the free web version:
**https://rpscripts.net/tools/fivem-backdoor-scanner/** (no account; the scan runs in
your browser and files are not uploaded).

> **No guarantee.** A clean result means none of these patterns matched. It does not
> mean a resource is safe. Escrow-encrypted (`.fxap`) files, compiled Lua and most
> JavaScript cannot be checked. Read the code you install, and get resources from
> their authors.

## What it checks

| Code | Severity | Confidence | What it flags |
| --- | --- | --- | --- |
| LAB-SEC-101 | warning | heuristic | `load`/`loadstring` inside a function passed to `PerformHttpRequest` or `PerformHttpRequestAwait` |
| LAB-SEC-102 | warning | heuristic | `load` of text that is only decoded at runtime (`string.char`, escaped bytes, decoder calls) |
| LAB-SEC-103 | warning | heuristic | Long escaped-byte, base64/hex or `string.char` data |
| LAB-SEC-104 | warning | heuristic | `GetConvar`/`GetConvarInt` of `sv_licenseKey`, `rcon_password`, `sv_tebexSecret`; `mysql_connection_string` only when the file also sends HTTP |
| LAB-SEC-105 | warning | heuristic | HTTP request whose address is a public raw IP, or an address decoded at runtime. A raw-IP string anywhere in a file that sends HTTP is enough |
| LAB-SEC-106 | warning | heuristic | `os.execute`, `io.popen`, writes outside the resource, `SaveResourceFile` into computed resources |
| LAB-SEC-107 | error | confirmed | Code after 400+ blanks on one line (space, tab, vertical tab or form feed) |
| LAB-PKG-004 | warning | heuristic | `.exe`, `.dll`, `.bat`, `.cmd`, `.ps1`, `.sh`, `.vbs`, `.jar`, `.scr` in a folder or archive. `.dll` is not flagged when a `*.net.dll` is present (C# resource) |
| LAB-PKG-005 | warning | confirmed | Archive entry with `..`, an absolute path or a drive letter |

Full texts (title, fix, references) are in [`rules/catalog.json`](rules/catalog.json).
Rule codes never change meaning; a retired rule keeps its code unused.

An **error** in the exit codes below is a finding with severity `error` (today only
LAB-SEC-107). LAB-PKG-005 is confirmed, but its severity is `warning`.

## What it does not do

- It does not run code, contact any server, or prove intent. Most rules are
  heuristics: a finding means "read this part", not "this is malware".
- It does not read escrow (`.fxap`), compiled Lua (`\x1bLua`) or nested archives.
- JavaScript files are checked for hidden code (LAB-SEC-107) only. Other rules are Lua.
- It does not look for leaked credentials such as Discord webhooks or Steam Web API
  keys (planned, see the roadmap).

## Use

This package is not published to npm, so `npx` cannot install it.

```sh
git clone https://github.com/Livvux/fivem-backdoor-scanner.git
cd fivem-backdoor-scanner
npm ci
npm run build
node cli/index.js ./resources            # a folder
node cli/index.js my-resource.zip        # a ZIP (up to 300 MB)
node cli/index.js ./resources --json     # machine-readable report
```

The folder walk skips `node_modules`, `.git` and `stream` directories.

Exit codes: `0` no finding, `1` warnings only, `2` at least one error, `3` the scan
could not run.

As a library (Node.js; the rule texts are read from `rules/catalog.json` next to the
package). After `npm run build` the entry is `dist/index.js`. Once the package is
installed as a dependency:

```ts
import { scanFiles } from "fivem-backdoor-scanner";
const report = scanFiles({ "server.lua": source });
console.log(report.verdict, report.findings);
```

From this repository, the same call is `import { scanFiles } from "./dist/index.js"`.

## Repository layout

```
rules/catalog.json      rule codes, severity, confidence, title, fix, references
rules/CHANGELOG.md      ruleset versions (YYYY.MM.N)
src/                    TypeScript rules (Lua via luaparse), ZIP reader, report
corpus/positive/        defanged samples that must trigger a rule (+ expected.json)
corpus/negative/        real-world-style code that must stay clean
tests/                  runs every corpus file against its expected codes
cli/index.js            command-line scanner (requires npm run build)
```

## Development

```sh
npm ci
npm test
npm run build
```

## Contributing

New patterns are welcome, especially from real incidents. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) first. In short: one rule or fix per pull request,
a defanged positive sample and at least one negative sample, no live malware, no
working C2 addresses, no credentials.

To report a backdoor family the rules miss without publishing it, see
[SECURITY.md](SECURITY.md).

## Roadmap

- Leaked-credential checks (Discord webhooks and bot tokens, `steam_webApiKey`,
  `sv_licenseKey` in shipped `server.cfg`)
- SQL dump check for leftover player data in server packs
- JavaScript (`server_script '*.js'`) loader patterns

## License

Apache-2.0 (see `LICENSE`). Disclaimer: the software is provided "as is",
without warranty of any kind; see the license text.

Maintained by [RPScripts](https://rpscripts.net).
