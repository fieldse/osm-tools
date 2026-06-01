---
status: APPROVED
project: osm — OpenSourceMalware CLI
go_version: "1.26"
module: github.com/fieldse/osm-tools
last_updated: 2026-06-02
---

# Implementation Plan

## Phases overview

1. **Foundation** — module scaffold, cobra root, dependency wiring, error taxonomy + exit-code mapping, domain types
2. **Config & auth** — config file persistence, secure-input prompt, auth resolution chain, `osm config`
3. **API client** — typed OSM client over `net/http`, rate-limited transport, response models, error classification
4. **check** — single lookup with type inference (first vertical slice, no cache)
5. **cache** — 24h file cache + caching `Lookup` decorator (built before sweep, its only consumer)
6. **sweep** — manifest parsers, bounded concurrent fan-out, table/JSON output, CI exit codes
7. **latest** — multi-ecosystem feed fetch, JSON output
8. **Hardening** — integration coverage, docs, release

Build-order rationale: `check` is the thinnest end-to-end slice that exercises the client, auth, and the error→exit mapping without cache or parsers — it validates the core plumbing. The **error taxonomy and exit-code mapping move into Foundation (phase 1)**, not hardening: every command's `RunE` returns through that mapping from day one, so retrofitting it later would touch every command. **Config/auth is its own phase (2)** because resolution precedence, file persistence, and terminal-masked prompting are three distinct concerns that the draft collapsed into one `internal/config` grab-bag. `cache` lands before `sweep` because sweep is its only consumer, and the cache is modelled as a **decorator over a `Lookup` interface**, not baked into the client. `latest` reuses the client but adds nothing to the critical path, so it comes late. **Tests are written within each phase** (table-driven, `httptest`), not deferred to a final phase; phase 8 is integration + release only.

---

## Architecture decisions

These resolve the ambiguities a per-step checklist tends to skip. Decide them up front; they shape package boundaries.

**Dependency injection, no globals.** There is no package-level client, config, or logger. The root command builds an `App` struct (or a small set of dependency fields) once and each subcommand closes over it. Concretely: subcommand constructors take the dependencies they need —

```
func newCheckCmd(deps *appDeps) *cobra.Command
func newSweepCmd(deps *appDeps) *cobra.Command
```

— and `appDeps` carries the resolved token, an `*client.Client`, and (for sweep) a cache-backed `Lookup`. Token resolution and client construction happen in the root command's `PersistentPreRunE`, after flags are parsed, so `--token` is available. This keeps cobra's wiring testable (a test builds `appDeps` with an `httptest`-backed client) and avoids `init()`-time global state.

**Where types live (no import cycles).** `client` owns the wire/response models (`CheckResult`, `LatestThreat`) since it decodes them. The *manifest* abstraction is a separate small domain type — a `Package{Name, Version, Ecosystem}` — that must **not** import `client`. Put it in `parser` and let `sweep` map `parser.Package` → a client call. Nothing in `internal/*` imports `cmd`. Dependency direction: `cmd → {client, cache, parser, output, config}`; `cache → client` (it stores `CheckResult`); everything else is leaf. No cycles.

**Interfaces at the consumer.** Do not define a `Lookup` interface inside `client` — define it where `sweep` consumes it:

```
// in cmd (or an internal/sweep package), the consumer side
type lookup interface {
    Check(ctx context.Context, q client.Query) (client.CheckResult, error)
}
```

`*client.Client` satisfies it directly; the caching decorator (phase 5) wraps anything satisfying it. `check` calls `*client.Client` concretely and skips the interface entirely (no cache, no substitution need). This is "accept interfaces, return structs" applied honestly — we only introduce the interface where substitution actually happens.

**Rate limiting lives in the HTTP transport, not call sites.** Implement the 60 req/min token bucket (`golang.org/x/time/rate` is the idiomatic choice; `rate.NewLimiter(rate.Every(time.Minute/60), burst)`) as a `http.RoundTripper` wrapper that calls `limiter.Wait(ctx)` before delegating. Inject it via `http.Client.Transport`. Benefit: every request — `check`, `sweep`, `latest` — is uniformly throttled with zero call-site discipline, and `ctx` cancellation propagates into the limiter wait. The limiter instance is shared (constructed once in `appDeps`) so concurrent sweep goroutines contend on one bucket. **Cache lookups happen before the request is issued, so cache hits never consume a token** — this composition is the whole point of putting the cache *outside* the client.

**Error taxonomy + exit codes (foundational).** Define a small typed-error vocabulary in an `internal/osmerr` (or co-located in `client` for API errors) package:

- Sentinel: `ErrNoToken`, `ErrNotFound`.
- Typed: `*APIError{StatusCode, Body}` (classify 401→auth, 429→rate-limit, 5xx→server) and `*UsageError` (bad flag/ecosystem/manifest). Callers branch with `errors.As`/`errors.Is`.

`RunE` returns these errors; a single mapping function in `main` (not cobra's default) converts them to exit codes:

- `0` — success / clean sweep
- `1` — operational failure (network, 5xx, auth, unreadable manifest, API unreachable)
- `2` — usage error (bad flags, missing required ecosystem, unknown ecosystem)
- `3` — **sweep gate triggered** (`--fail-on-any` and at least one `malicious: true`)

Note exit `3`: a malicious hit under `--fail-on-any` is a *successful run with a policy verdict*, not an error. Returning it as a plain error muddies the taxonomy. Model it as a distinct typed value (e.g. `RunE` returns a `*GateTriggered` sentinel that the mapper recognizes) or have sweep's `RunE` call a small "exit with code" path. Pick one and document it; the mapper in `main` is the single source of truth.

**`docker` (CLI) vs `container` (API).** The user-facing type is `docker`; the API's `report_type` value is `container` (per the API guide: `package|container|repository|url|domain|ip|wallet`). The draft never reconciled this. Keep `docker` as the CLI surface (matches README/spec), and map `docker → container` at the client boundary when building the request. Centralize this mapping in one place in `client`.

**Context propagation.** Every client method takes `ctx context.Context` as its first parameter. Cobra commands derive a root context (`signal.NotifyContext` for SIGINT) in `main` and thread it through `cmd.ExecuteContext` so Ctrl-C cancels in-flight requests and the rate-limiter wait.

---

## Steps detail

### **1. Foundation**: scaffold, wiring, error/exit model

Stand up the module, CLI skeleton, dependency wiring, and the error→exit contract everything else returns through.

- [x] 1.1 Init module: `go mod init github.com/fieldse/osm-tools`, target Go 1.26; add `github.com/spf13/cobra` and `golang.org/x/time/rate`
- [x] 1.2 `main.go`: build root signal context (`signal.NotifyContext` on SIGINT/SIGTERM), call `cmd.Execute(ctx)`, and map the returned error to an exit code via the single mapping function
- [x] 1.3 Root command (`cmd/root.go`): persistent `--token`/`-t` flag, base-URL constant; `PersistentPreRunE` resolves token + constructs `appDeps` (deferred token resolution until phase 2 lands)
- [x] 1.4 Dependency wiring: define `appDeps` struct (resolved token, `*client.Client`, shared rate limiter, optional cache-backed `lookup`); subcommand constructors take `*appDeps` — no package-level globals, no `init()` state
- [x] 1.5 Error taxonomy: `osmerr` package (or co-located) with sentinels `ErrNoToken`/`ErrNotFound`, typed `*APIError`, `*UsageError`, and the `GateTriggered` signal for sweep
- [x] 1.6 Exit-code mapper in `main`: `0` success, `1` operational, `2` usage, `3` gate-triggered; this is the only place exit codes are decided
- [x] 1.7 Unit test: exit-code mapper table (each error category → expected code)

### **2. Config & auth**: persistence, prompt, resolution

Three separable concerns the draft merged. Keep file I/O, the masked prompt, and the precedence resolver distinct.

- [x] 2.1 Config store (`internal/config`): load/save `~/.osm/config.json`; create `~/.osm` with `0700` and the file with `0600`; tolerate a missing file (zero value), surface a parse error on corrupt file
- [x] 2.2 Auth resolver: pure function `ResolveToken(flag string, env, fileToken string) (string, error)` implementing precedence `--token` → `OSM_API_KEY` → config file; returns `ErrNoToken` when all empty — kept pure so it is trivially table-tested
- [x] 2.3 Wire resolution into root `PersistentPreRunE`: read flag + env + loaded config, call `ResolveToken`, stash on `appDeps`; commands that need auth fail fast with an actionable `ErrNoToken` message
- [x] 2.4 `osm config` command: masked terminal prompt (`golang.org/x/term` ReadPassword; the one justified non-stdlib addition for hidden input — note in deps), trim + reject empty, optionally sanity-check the `osm_` prefix as a warning (not a hard error), save via the config store, print the written path
- [x] 2.5 Tests: `ResolveToken` precedence table; config store round-trip + corrupt-file + perms (use `t.TempDir()`, override home dir via an injected path, not the real `~`)

### **3. API client**: typed client, rate-limited transport, error classification

One `client` package that `check`, `sweep`, and `latest` call into. Returns concrete structs; no interface defined here.

- [x] 3.1 Response models: `CheckResult` (`Malicious`, `SeverityLevel`, `Description`, `Tags`, `FirstSeen`, `LastSeen`, `LastOSMScore`, `LastScannedAt`, `ScanCount`, `ThreatID` from `details.threat_id`); `LatestThreat` — field names/JSON tags confirmed against a live response, but model the documented fields now
- [x] 3.2 `Query` request type for check: `{Type, Identifier, Ecosystem, Version}`; map CLI `docker` → API `report_type=container` here, at the boundary
- [x] 3.3 `Client` constructor: takes base URL, token, and an `*http.Client`; sets Bearer auth per-request; `New(...)` returns `*Client` (struct, not interface)
- [x] 3.4 Rate-limited `RoundTripper`: wraps a base transport, calls `limiter.Wait(ctx)` before each round trip; limiter injected so it can be shared and so tests can use a permissive limiter
- [x] 3.5 Endpoints: `Check(ctx, Query) (CheckResult, error)` → `GET /check-malicious`; `QueryLatest(ctx, ecosystem) ([]LatestThreat, error)` → `GET /query-latest`
- [x] 3.6 Error classification: non-2xx → `*APIError` with status + body; 401→auth, 429→rate-limit (surface `Retry-After` if present), 5xx→server; network/transport errors wrapped with `%w` and classified as operational; JSON decode errors wrapped distinctly
- [x] 3.7 Tests (`httptest`): 200 (malicious true/false), 401, 429 (+Retry-After), 5xx, network failure (closed server), malformed-JSON body — assert each maps to the right error category via `errors.As`

### **4. check**: single lookup with type inference

First user-facing slice. No cache. Calls `*client.Client` concretely.

- [x] 4.1 Type inference: ordered rules — IP pattern → `ip`; contains `:` or a known registry prefix → `docker`; contains `.` → `domain`; else `package` (open question: exact registry-prefix list, see open questions)
- [x] 4.2 `--type`/`-T` override: explicit flag short-circuits inference; validate it against the supported set (`package|domain|ip|docker`) → `*UsageError` on unknown
- [x] 4.3 Validation: `package` type with no `-e`/`--ecosystem` → `*UsageError` with the exact remedy in the message
- [x] 4.4 Detail-block formatter (`internal/output`): name, type, severity, description, tags, first_seen; takes a `CheckResult`, writes to an `io.Writer` (injected for test capture)
- [x] 4.5 Wire command: resolve type → build `Query` → `client.Check(ctx, q)` → render; exit `0` regardless of malicious verdict (lookup tool, not a gate). A 401 from the client surfaces as the auth-failure exit `1` via the mapper
- [x] 4.6 Tests: inference table (every spec example incl. the no-ecosystem error case); formatter golden output; command-level test with an `httptest`-backed client

### **5. cache**: 24h response cache + Lookup decorator

Built before sweep; sweep is the only consumer. Cache sits *outside* the client so hits never burn a rate token.

- [x] 5.1 Cache store (`internal/cache`): keyed by `type:ecosystem:name:version`, value = `CheckResult` + `StoredAt`; backed by `~/.osm/cache.json`; tolerate missing/corrupt file (treat as empty, log-and-continue, never fail the command)
- [x] 5.2 TTL: entries older than 24h are misses; lazy expiry on read (don't rewrite the file just to evict)
- [x] 5.3 Caching decorator: a type wrapping any `lookup` (the consumer-side interface) — on `Check`, compute key, return fresh cache hit, else delegate, then write-back. Concurrency: the in-memory map is guarded by a `sync.RWMutex`; the file is read once at start and flushed once at end of a sweep (not per-write) to avoid write storms
- [x] 5.4 Decide flush strategy explicitly: load-on-construct, hold in memory under the mutex during the run, persist once on sweep completion (including partial results on cancellation). Document that `check` does not use the cache at all
- [x] 5.5 Tests: TTL boundary (just-under / just-over 24h via injected clock — pass a `now func() time.Time`), corrupt-file tolerance, decorator hit/miss/write-back, concurrent access under `-race`

### **6. sweep**: manifest scan for CI gates

The concurrency-heavy phase. Make the fan-out model explicit.

- [x] 6.1 Parser dispatch (`internal/parser`): `Parse(path) ([]Package, error)` where format is chosen by filename; `Package{Name, Version, Ecosystem}` is the domain type owned here (must not import `client`); unknown filename → `*UsageError`
- [x] 6.2 `package.json` parser: `dependencies` + `devDependencies` only; ecosystem `npm`
- [x] 6.3 `package-lock.json` parser: direct deps only (not the full resolved tree); ecosystem `npm`
- [x] 6.4 `requirements.txt` parser: name + pinned version; skip comments, blank lines, and `-r`/`-c` includes; ecosystem `pypi`
- [x] 6.5 `poetry.lock` parser: top-level `[[package]]` entries; ecosystem `pypi`
- [x] 6.6 Dedupe: collapse identical `name+version+ecosystem` into a unique set before any API calls
- [x] 6.7 Fan-out model: use `errgroup.Group` with `g.SetLimit(N)` to bound in-flight goroutines (N small, e.g. 8 — the rate limiter is the real throttle, the bound just caps memory/socket use). Each goroutine calls the **cache-backed `lookup`**; the shared rate-limited transport serializes actual network egress at 60/min. Derive a child context from the command context; `errgroup` cancels siblings when a worker returns a hard error (network/5xx/auth). A `malicious: true` result is **not** an error — it does not cancel the group; collect it
- [x] 6.8 Result collection + ordering: workers write into a pre-sized `[]Result` slice indexed by input position (no shared-append races, deterministic output), or into a channel drained by a single collector. Preserve manifest order in output regardless of completion order
- [x] 6.9 Table output (`internal/output`): `package | version | status | severity | first_seen`, all packages shown including clean ones; write to injected `io.Writer`
- [x] 6.10 JSON output (`-o json`): valid JSON array of results; validate `-o` value (`table|json`) → `*UsageError` on unknown
- [x] 6.11 Exit semantics: any hard error (network/5xx/auth/unreadable manifest) → operational exit `1` (and cancel remaining work). Clean run → exit `0` + summary. `--fail-on-any` with ≥1 hit → return the `GateTriggered` signal → exit `3`. The mapper in `main` owns the code; sweep only returns the right typed value
- [x] 6.12 Cache flush: persist the cache once on completion (and on context cancellation, flush what was gathered) per the decorator's decided strategy
- [x] 6.13 Tests: each parser against fixture files (incl. malformed/edge cases); dedupe; concurrent fan-out under `-race` with an `httptest` server; gate exit-code behaviour (clean vs hit vs network failure) via the mapper

### **7. latest**: recent-threat feed

- [x] 7.1 Ecosystem flag: `-e npm,pypi` comma-separated; empty = all 8 (`npm,pypi,maven,nuget,rubygems,packagist,crates,go`)
- [x] 7.2 Validation: unknown ecosystem value → `*UsageError` listing valid options (exit `2`)
- [x] 7.3 Fetch: one `QueryLatest(ctx, eco)` per selected ecosystem; for multiple ecosystems use `errgroup` (same shared rate limiter throttles egress) — but cancellation-on-error and ordered, per-ecosystem result assembly mirror sweep
- [x] 7.4 JSON output: default shape decided after inspecting a live response — see open questions; until then model as grouped-by-ecosystem (`{ "npm": [...], "pypi": [...] }`) since the API is inherently per-ecosystem
- [x] 7.5 Tests: ecosystem parsing/validation table; multi-ecosystem fetch against `httptest`

### **8. Hardening**: integration, docs, release

- [ ] 8.1 End-to-end smoke test: build the binary, run `check`/`sweep`/`latest` against an `httptest` server wired via base-URL override (env or hidden flag) — exercises the real cobra path, not just unit seams
- [ ] 8.2 Rate-limiter integration test: drive many concurrent requests through the real transport and assert no burst exceeds 60/min (sample request timestamps; use a faster limiter rate in test to keep it quick)
- [ ] 8.3 Error-message audit: actionable text for missing token (`ErrNoToken`), bad ecosystem, unreadable/unknown manifest, auth failure — assert remediation is in the message
- [ ] 8.4 Docs: confirm every README example runs; align CLAUDE.md architecture block with final structure (note: CLAUDE.md still lists a `watch.go` command that is out of scope — remove it)
- [ ] 8.5 Release: `go build ./...` clean, `go vet ./...`, `go test -race ./...` green, tag `v0.1.0`

---

## Open questions

- **`latest` output shape** (combined array vs. grouped-by-ecosystem) — defer until a live response is seen (7.4); leaning grouped since the API is per-ecosystem.
- **Docker registry-prefix list for inference** — which prefixes (`ghcr.io/`, `quay.io/`, `docker.io/`, …) does the `docker`/`container` inference recognize? Confirm against OSM docs (4.1).
- **`CheckResult` JSON field names** — model documented fields now (`severity_level`, `details.threat_id`, `last_scanned_at`, etc.), but verify exact tags + nullability against a live `check-malicious` response before locking the struct (3.1).
- **`docker` → `container` confirmed?** — API guide lists `report_type=container`; confirm `docker` isn't also accepted, and that `container` is the value for Docker images specifically (3.2).
- **Base-URL override for tests/staging** — expose via a hidden flag or `OSM_BASE_URL` env? Needed for 8.1; pick the least surface-expanding option (likely an unexported test seam + env var, no public flag).
- **`429` handling policy** — does sweep retry with backoff on rate-limit, or fail fast to exit `1`? The limiter should make 429s rare; decide whether a stray 429 is operational-fatal or triggers one bounded retry honoring `Retry-After`.
