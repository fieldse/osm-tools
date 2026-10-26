---
status: ACCEPTED (approved by the maintainer, 2026-10-25)
date: 2026-10-25
deciders: dependency-auditor; user
---

# 0002: Import golang.org/x/sys directly

## Decision

Move **`golang.org/x/sys` at `v0.44.0`** from `// indirect` to the direct `require` block, so `osm config` can save and restore terminal echo state itself.

Verdict: **CLEAR WITH CONDITIONS**. It is a Go project module, it is already in the graph at this exact version through `golang.org/x/term`, and the one advisory that touches nearby versions is fixed in v0.44.0.

Pin (go.sum format, unchanged from the current go.sum):

```
golang.org/x/sys v0.44.0 h1:ildZl3J4uzeKP07r2F++Op7E9B29JRUy+a27EibtBTQ=
golang.org/x/sys v0.44.0/go.mod h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw=
```

go.mod line, in the direct `require` block:

```
golang.org/x/sys v0.44.0
```

Upstream source: `https://go.googlesource.com/sys`, tag `v0.44.0`, commit `fb1facd76f95fa87c151018200ea5e4892ff115d`.

## Why a direct import is needed

- `osm config` needs to read and restore terminal echo state on its own. `golang.org/x/term` covers the hidden prompt but does not expose all of the termios control the command needs.
- The standard library has no portable termios API. `syscall` would mean hand-written per-OS ioctl constants.
- The module is already compiled into the binary. Importing it directly adds no new code source.

## Evidence (collected 2026-10-25)

| Check | Result |
|---|---|
| Maintainer | The Go project. Source is `go.googlesource.com/sys`, served under the `golang.org/x` vanity path. Changes go through Gerrit review by the Go team. |
| Release | v0.44.0, published to proxy.golang.org 2026-04-23: 185 days old. Latest is v0.49.0 (2026-10-06). Monthly release cadence. |
| OSV, v0.44.0 | `api.osv.dev` Go ecosystem query for this version: no vulns. |
| OSV, all versions | GO-2022-0493 / CVE-2022-29526 (fixed 2022). GO-2026-5024 / CVE-2026-39824: integer overflow in `windows.NewNTUnicodeString`, fixed in v0.44.0. Neither affects v0.44.0. |
| OpenSourceMalware | `osm check golang.org/x/sys -e go -T package` returned `status: CLEAN`. That means "not in the OSM database", not "safe". |
| Checksum | go.sum hashes match `sum.golang.org/lookup/golang.org/x/sys@v0.44.0` (tlog entry 53780131). |
| Transitive deps | **0.** The v0.44.0 go.mod has no `require` lines. |
| Already in graph | Yes. `golang.org/x/term v0.43.0` requires `golang.org/x/sys v0.44.0`. Version, go.sum and build list stay the same. No new module or publisher enters the graph. |
| Install/build-time code | Go modules have no install hooks. The module uses `unsafe` and assembly by design (it is the syscall layer); that code is already in the current binary. |
| License | BSD-3-Clause, same as the rest of `golang.org/x`. |

## Conditions

1. **go.mod diff only.** The only change is removing `// indirect` from the `golang.org/x/sys v0.44.0` line (`go mod tidy` moves it to the direct block). go.sum must not change. Any other module or version change in either file stops the change and comes back for audit.
2. **Integrity.** `go mod verify` passes. Do not set `GONOSUMDB`, `GONOSUMCHECK`, `GOPRIVATE`, `GOINSECURE` or `GOFLAGS=-mod=mod` for this module.
3. **Narrow use.** Import only the terminal-control packages (`golang.org/x/sys/unix`, and `golang.org/x/sys/windows` if Windows support needs it) from the `osm config` code path.
4. **Register entry.** The `## Dependencies` section of `CLAUDE.md` gets this line in the same change:
   `- \`golang.org/x/sys\` v0.44.0 — terminal echo control for \`osm config\` (decision 0002)`
5. **Upgrades.** A later bump goes through this gate again. A bump of `golang.org/x/term` that raises this module's version counts as a bump of this module.
