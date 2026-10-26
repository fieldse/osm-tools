---
status: ACCEPTED (approved by the maintainer, 2026-10-25)
date: 2026-10-25
deciders: dependency-auditor; user
requirement: R12 (pnpm and yarn lockfile parsers)
---

# 0001: YAML library for pnpm-lock.yaml and yarn berry yarn.lock

## Decision

Use **`go.yaml.in/yaml/v3` at `v3.0.5`**.

Verdict: **CLEAR WITH CONDITIONS**. It is the YAML org's official, maintained successor to `gopkg.in/yaml.v3`, it has no requirements of its own, and the module graph already contains it through cobra.

Pin (go.sum format):

```
go.yaml.in/yaml/v3 v3.0.5 h1:N6y/pJk8buWs9NY5ERU2HSMfm+IuD/OtfdAnq6kESPw=
go.yaml.in/yaml/v3 v3.0.5/go.mod h1:HVTZu1O7/Vkt2N+BFy8Zza+lnLsABggaTM2ZpNIGuKg=
```

go.mod line, in the direct `require` block:

```
go.yaml.in/yaml/v3 v3.0.5
```

Upstream source: `https://github.com/yaml/go-yaml`, tag `v3.0.5`, commit `e16c7af9361b241fa02d91582fb59ce4954d8afc`, branch `v3`.

## Why a library is needed

- pnpm-lock.yaml (v6 and v9) and yarn berry yarn.lock are YAML: quoted scoped keys, nested maps, and in pnpm v6 flow-style values. A hand parser would have to implement enough of YAML 1.2 to get these right.
- AT-12.12 requires malformed YAML to produce an error. That needs a real parser that rejects bad input.
- The standard library has no YAML package.
- Yarn v1 is not YAML and will be hand-parsed. It does not use this library.

## Evidence (collected 2026-10-25)

| Check | Result |
|---|---|
| Vanity import | `go.yaml.in/yaml/v3?go-get=1` serves `go-import go.yaml.in/yaml/v3 git https://github.com/yaml/go-yaml` (GitHub Pages host) |
| Maintainer | `github.com/yaml` organisation, which maintains the YAML spec. Repo README: "Maintained by the YAML organization". Top committers: ingydotnet (YAML spec co-author, 314 commits), niemeyer (original author, 244), ccoVeille, rogpeppe, plus others. Not a single-person project. |
| Successor status | The old repo `go-yaml/yaml` (what `gopkg.in/yaml.v3` serves) is archived. Its README reads "THIS PROJECT IS UNMAINTAINED". `yaml/go-yaml` lists v3 as "Stable, frozen API; security fixes only" at `go.yaml.in/yaml/v3`. |
| Repo | Created 2025-04-25 (the org took over the code then; it has history back to 2010). Last push 2026-10-24. Not archived. |
| Latest release | v3.0.5, published to proxy.golang.org 2026-07-26: 91 days old, above the 14-day floor. |
| Release cadence | v3.0.2, v3.0.3 (2025-06-02), v3.0.4 (2025-06-29), v3.0.5 (2026-07-26). This matches a branch that only gets security fixes. |
| v3.0.4 → v3.0.5 diff | 10 commits. Non-test source changes are comment reformatting only (`parserc.go`, `yamlh.go`). go.mod drops `gopkg.in/check.v1` and retracts `[v3.0.0, v3.0.1]`. Test files moved to the standard `testing` package. A CodeQL workflow was added. |
| Code vs gopkg.in/yaml.v3 v3.0.1 | The changes that are not comments: a panic-to-error guard for unhashable merge keys (`decode.go`), the `Encoder.CompactSeqIndent` option, and gofmt fixes. |
| OSV, v3.0.5 | `api.osv.dev` Go ecosystem: no vulns. All-version history: none ever recorded for this module path. |
| OpenSourceMalware | `osm check go.yaml.in/yaml/v3 -e go -T package` → `status: CLEAN`. This means "not in the OSM database", not "safe". |
| License | Dual license: MIT for the libyaml-port files (`apic.go emitterc.go parserc.go readerc.go scannerc.go writerc.go yamlh.go yamlprivateh.go`), Apache-2.0 for the rest. Both are compatible with this project. |
| Transitive deps | **0.** The v3.0.5 go.mod has no `require` lines. |
| Already in graph | Yes. `github.com/spf13/cobra v1.10.2` requires `go.yaml.in/yaml/v3 v3.0.4`. go.sum already has `go.yaml.in/yaml/v3 v3.0.4/go.mod`. With MVS, v3.0.5 replaces v3.0.4 for the whole build. No new publisher enters the graph. |
| Install/build-time code | Go modules have no install hooks. The proxy zip was unpacked in a scratch dir and grepped: no `//go:generate`, no cgo (`import "C"`), no `os/exec`, `net`, `syscall`, `unsafe` or `plugin` imports outside tests. The three `init()` functions fill tag/resolve lookup tables and a reflect type. Non-Go files: LICENSE, NOTICE, README.md, two GitHub workflow files. |
| Checksum | The h1 hash computed locally from the proxy zip matches `sum.golang.org/lookup/go.yaml.in/yaml/v3@v3.0.5` (tlog entry 58122890). |
| Upstream signature | None. `v3.0.5` is a lightweight tag, and the commit is unsigned (GitHub `verification.reason: unsigned`). Integrity rests on the Go checksum database, which is a transparency log. |
| Local Go env | `GOPROXY=https://proxy.golang.org,direct`, `GOSUMDB=sum.golang.org`, `GONOSUMDB`/`GONOSUMCHECK`/`GOPRIVATE`/`GOINSECURE`/`GOFLAGS` empty. Checksum verification is on. |

## Conditions

1. **User approval.** The user agrees to `go.yaml.in/yaml/v3@v3.0.5` by name before go.mod is touched. The plan's scope decision put the lockfiles in scope. It did not approve a specific package.
2. **Exact pin.** The implementer runs `go get go.yaml.in/yaml/v3@v3.0.5`, then `go mod tidy`. The go.sum diff must include the two h1 lines above exactly. The go.mod diff must be the single `require` line. Any other new module in either diff stops the change and comes back for audit.
3. **Integrity.** `go mod verify` passes. Do not set `GOFLAGS=-mod=mod`, `GONOSUMDB`, `GONOSUMCHECK`, `GOPRIVATE` or `GOINSECURE` for this module.
4. **Only the parser imports it.** `go.yaml.in/yaml/v3` is imported only from `internal/parser`, the pnpm and yarn-berry files.
5. **Register entry.** The `## Dependencies` section of `CLAUDE.md` gets this line in the same change (during the R13 docs step at the latest):
   `- \`go.yaml.in/yaml/v3\` v3.0.5 — pnpm-lock.yaml and yarn berry yarn.lock (decision 0001)`
6. **Hostile input.** Lockfiles are untrusted input. Decode into typed structs. Do not decode into `interface{}` for whole-file walks. Handing this to the security engineer: a size cap on the lockfile read (for example `io.LimitReader`) and whether to `recover()` around decode, since v3 only turns its own `yamlError` panics into errors.
7. **Upgrades.** Any later bump (including v4.0.0 GA) goes through this gate again and gets its own decision record.

## Rejected alternatives

- `go.yaml.in/yaml/v4` v4.0.0-rc.6 (2026-06-17): prerelease only. The README says v4.0.0 "is not released yet", so the API can still change. Re-evaluate after GA plus 14 days.
- `gopkg.in/yaml.v3` v3.0.1 (2022-05-27): upstream `go-yaml/yaml` is archived and marked unmaintained, so no further security fixes will ship. Prior advisory GHSA-hp87-p4gw-j4gq / CVE-2022-28948 is fixed in v3.0.1. It would also add a second YAML module next to cobra's `go.yaml.in/yaml/v3`.
- `github.com/goccy/go-yaml` v1.19.2 (2026-01-08, MIT, 0 deps, OSV and OSM clean): one personal account holds the keys (goccy, 605 commits against 22 for the next contributor; user-owned repo). It would add a new publisher to the graph when an org-maintained module is already there.
