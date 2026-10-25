---
status: APPROVED
branch: fix/osm-api-conformance
last_updated: 2026-10-25
---

# API conformance fixes

Fixes the false-CLEAN bugs and API drift found by a live review of the CLI against the OSM API on 2026-10-25.

## Scope decisions (user, 2026-10-25)

- **Repo / URL / wallet lookups:** rejected with a usage error (exit 2). Full support stays out of scope.
- **REVIEW verdict:** trips `sweep --fail-on-any` (exit 3), same as MALICIOUS.
- **Lockfiles:** `pnpm-lock.yaml` and `yarn.lock` (v1 and berry) are in scope. The YAML library goes through the dependency audit first.

## API facts the tests encode

Observed live on 2026-10-25. Fixtures must use these shapes.

- **Matching:** exact and case-sensitive on the package name. No prefix (`npm/x`), no normalisation.
- **`ecosystem` param:** case-sensitive. Valid package ecosystems: `npm pypi maven nuget rubygems packagist crates go vscode openvsx skills brew`.
- **Version match:** exact token match against `version_info`. A range (`^1.2.3`) or an unlisted version returns `malicious:false` plus `warning` and `known_malicious_versions`.
- **Hit with exact version:**
  `{"malicious":true,"version":"1.14.1","osm_url":"https://opensourcemalware.com/npm/axios","threat_count":1,"details":{"threat_id":"a5b0…","severity_level":"critical","description":"…","version_info":"1.14.1, 0.30.4"}}`
- **Hit, no version sent:** same shape, `"version":null`.
- **All versions bad:** `details.version_info` is `"all"`, blank, or null.
- **Version miss with warning:**
  `{"malicious":false,"version":"^1.14.0","warning":"This package has known malicious versions","known_malicious_versions":["1.14.1, 0.30.4"],"osm_url":"…","details":null}`
- **Not found:** `{"malicious":false,"message":"Resource not found in malicious database", …}` with no `details`.
- **Maven:** stored as either `group:artifact` or bare `artifact`, varying by record.
- **429 bodies:** per-minute `{"error":"Rate limit exceeded. Maximum 60 requests per minute (standard tier)."}`; daily `{"error":"Daily quota exceeded: 2000/2000 requests …","tier":"free",…}`.

## Verdict rules (shared by `check` and `sweep`)

An exact version is a non-empty version that is not a range (see R3).

| Verdict | When |
|---|---|
| MALICIOUS | `malicious:true` and (`version_info` is all/blank/null, or the query sent an exact version) |
| REVIEW | `malicious:true`, no exact version sent, and `version_info` lists specific versions |
| REVIEW | `malicious:false` and `warning` or `known_malicious_versions` is non-empty |
| REVIEW | result came only from the Maven artifactId fallback (R9) |
| CLEAN | everything else |

## Requirements and test conditions

Acceptance tests live in `*_acceptance_test.go` files and `testdata/acceptance/`. They are written first, committed, and locked (see Anti-cheat). Tests are black-box: they drive `newCheckCmd`, `newSweepCmd`, `newLatestCmd`, `parser.Parse`, and `client.New(...).Check` against `httptest` servers that record every request. They must compile against the pre-fix code.

### R1 — `-e` forces package type
- [ ] **AT-1.1** `check smiletime.pandatask -e vscode` sends `report_type=package`.
- [ ] **AT-1.2** `check org.mvnpm:posthog-node -e maven` sends `report_type=package`.
- [ ] **AT-1.3** `check github.com/gobank-modules/web3-integration -e go` sends `report_type=package`.
- [ ] **AT-1.4** `check Zendesk.OAuth -e nuget` sends `report_type=package`, identifier unchanged (case kept).
- [ ] **AT-1.5** `check lodash.merge -e npm` sends `report_type=package`.
- [ ] **AT-1.6** `--type domain` still overrides: `check evil.com -e npm --type domain` sends `report_type=domain`.
- [ ] **AT-1.7** No `-e`, no `--type`: `evil.com` → domain, `1.2.3.4` → ip, `nginx:latest` → container (regression guards).

### R2 — verdicts, `warning` field, REVIEW gate
- [ ] **AT-2.1** check: hit with `version_info:"1.14.1, 0.30.4"` and no `--version` → `status:      REVIEW`.
- [ ] **AT-2.2** check: same hit with `--version 1.14.1` → `status:      MALICIOUS`.
- [ ] **AT-2.3** check: hit with `version_info:"all"`, null, or blank, no `--version` → MALICIOUS (three cases).
- [ ] **AT-2.4** check: `malicious:false` + `warning` + `known_malicious_versions` → REVIEW; output contains the known versions.
- [ ] **AT-2.5** check: not-found response → `status:      CLEAN`.
- [ ] **AT-2.6** check: exit 0 for MALICIOUS, REVIEW and CLEAN.
- [ ] **AT-2.7** sweep JSON: a REVIEW row has `"status":"REVIEW"`.
- [ ] **AT-2.8** sweep `--fail-on-any` with only a REVIEW row returns `*osmerr.GateTriggered` (exit 3).
- [ ] **AT-2.9** sweep `--fail-on-any` with only CLEAN rows returns nil.
- [ ] **AT-2.10** sweep table shows `REVIEW` for a REVIEW row.

### R3 — never send version ranges
- [ ] **AT-3.1** package.json `"axios":"^1.14.0"` → request has no `version` param, or an empty one.
- [ ] **AT-3.2** Each of `~1.2.3`, `>=1.0.0`, `1.x`, `*`, `latest`, `1.2.3 - 2.0.0`, `^1 || ^2`, `workspace:*`, `file:../x`, `git+https://…`, `https://…/x.tgz` → no version sent.
- [ ] **AT-3.3** `"1.2.3"`, `"=1.2.3"` and `"1.2.3-beta.1"` → `version=1.2.3` / `1.2.3` / `1.2.3-beta.1`.
- [ ] **AT-3.4** npm alias `"my-axios":"npm:axios@1.14.1"` → identifier `axios`, version `1.14.1`.
- [ ] **AT-3.5** End to end: package.json `axios ^1.14.0` against a server returning the "hit, no version sent" shape with specific versions → sweep row is REVIEW, not clean.
- [ ] **AT-3.6** package-lock.json root dep whose `node_modules/<name>` entry is missing falls back to the spec, with the same range rules applied.

### R4 — show affected versions and link
- [ ] **AT-4.1** check output contains a `versions:` line with `version_info` when present.
- [ ] **AT-4.2** check output contains a `url:` line with `osm_url` when present.
- [ ] **AT-4.3** sweep JSON rows include `affected_versions` and `osm_url`.

### R5 — ecosystem list
- [ ] **AT-5.1** `latest -e vscode,openvsx,skills,brew` is accepted, with one request per ecosystem.
- [ ] **AT-5.2** `latest` with no `-e` queries all 12 package ecosystems.
- [ ] **AT-5.3** `latest -e cargo` → UsageError.

### R6 — validate `-e` in check
- [ ] **AT-6.1** `check x -e cargo` → UsageError, zero HTTP requests.
- [ ] **AT-6.2** `check tns-py -e PyPI` → request sends `ecosystem=pypi` (lowercased before validation).
- [ ] **AT-6.3** The usage message lists the valid ecosystems.

### R7 — reject unsupported asset types
- [ ] **AT-7.1** `check https://github.com/Owner/repo` → UsageError mentioning "not supported", zero requests.
- [ ] **AT-7.2** `check http://example.com/payload` → UsageError, zero requests.
- [ ] **AT-7.3** `check 0x1234567890abcdef1234567890abcdef12345678` → UsageError, zero requests.
- [ ] **AT-7.4** `--type repository`, `--type url` and `--type wallet` → UsageError, zero requests.
- [ ] **AT-7.5** `check aquasec/trivy:0.69.5` still → container (regression guard).

### R8 — response model matches the API
- [ ] **AT-8.1** `client.Check` decodes the "hit with exact version" fixture without error. Verified black-box through check output (severity, versions, url all printed).
- [ ] **AT-8.2** `client.Check` decodes the warning fixture with `"details":null` without error.
- [ ] **AT-8.3** Sweep table and JSON no longer carry an always-empty `first_seen` column. JSON rows have no `first_seen` key.
- [ ] **AT-8.4** `latest` JSON output keeps `resource_identifier`, `status`, `osm_url` and `verified_at` from the fixture.

### R9 — Maven dual lookup
- [ ] **AT-9.1** `check io.github.xz-java:xz-java -e maven`: the server returns not-found for the full name and a hit for `xz-java`. Exactly 2 requests in order (full, then artifact); verdict REVIEW; output names the artifactId fallback.
- [ ] **AT-9.2** `check org.mvnpm:posthog-node -e maven` with a hit on the full name → exactly 1 request; verdict follows the normal rules.
- [ ] **AT-9.3** `check xz-java -e maven` (no colon) → exactly 1 request.
- [ ] **AT-9.4** Full name returns the warning shape → no fallback request (1 request), verdict REVIEW.

### R10 — normalise domains
- [ ] **AT-10.1** `check Server-Genimi-Check.Vercel.App` sends `resource_identifier=server-genimi-check.vercel.app`.
- [ ] **AT-10.2** A trailing dot is stripped: `evil.com.` → `evil.com`.
- [ ] **AT-10.3** Package identifiers are never lowercased (`Zendesk.OAuth -e nuget` keeps case).

### R11 — 429 handling
- [ ] **AT-11.1** The server returns 429 with `Retry-After: 0` once, then 200 → `Check` succeeds; 2 requests.
- [ ] **AT-11.2** The server always returns 429 with `Retry-After: 0` → `*osmerr.APIError` with status 429 after exactly 4 requests (1 + 3 retries).
- [ ] **AT-11.3** A daily-quota 429 body → error after exactly 1 request (no retry); the error text contains "Daily quota".
- [ ] **AT-11.4** A context cancelled during a retry wait returns promptly (under 2s) with a context error. Use `Retry-After: 30`.
- [ ] **AT-11.5** A 500 is not retried (1 request).

### R12 — pnpm-lock.yaml and yarn.lock
- [ ] **AT-12.1** pnpm v9 (`lockfileVersion: '9.0'`), single importer `.` → direct deps from `dependencies`, `devDependencies` and `optionalDependencies`, with exact `version`.
- [ ] **AT-12.2** pnpm peer suffix is stripped: `3.2.7(@types/node@22.20.0)(jsdom@25.0.1)` → `3.2.7`.
- [ ] **AT-12.3** pnpm monorepo: multiple importers → the union of every importer's direct deps, deduped.
- [ ] **AT-12.4** pnpm `link:` / `file:` / `workspace:` versions are skipped.
- [ ] **AT-12.5** pnpm v6 (`lockfileVersion: '6.0'`) single-project format → parsed the same way.
- [ ] **AT-12.6** pnpm alias `version: string-width@4.2.3` with a different key → identifier `string-width`, version `4.2.3`.
- [ ] **AT-12.7** Scoped names are kept intact: `'@scope/pkg'` → `@scope/pkg`.
- [ ] **AT-12.8** Transitive-only packages (in `packages:`/`snapshots:` but not an importer dep) are NOT returned.
- [ ] **AT-12.9** yarn v1 with a sibling package.json → only direct deps; version resolved from the matching `name@spec` entry, including multi-spec keys `"a@^1.0.0", "a@^1.1.0":`.
- [ ] **AT-12.10** yarn berry (`__metadata:`) with a sibling package.json → resolves `name@npm:spec` entries.
- [ ] **AT-12.11** yarn.lock with no sibling package.json → error; exit code 1 (operational), not 0.
- [ ] **AT-12.12** Malformed pnpm YAML → error, exit 1.
- [ ] **AT-12.13** `parser.Parse` on an unknown filename still → UsageError listing every supported manifest, including the two new ones.
- [ ] **AT-12.14** Ecosystem is `npm` for every package from both formats.

### R13 — docs
- [ ] Skill `security-malware-osm/SKILL.md`: ecosystems, rate limits (60/min, 2000/day), REVIEW verdict, new manifests, unsupported types.
- [x] Project `CLAUDE.md`, `README.md` and the `sweep --file` help text reflect the new manifests, REVIEW and exit behaviour.
- [ ] Local agent config points at the current source checkout (local-only, not committed).

## Anti-cheat rules

1. Acceptance tests are written by test agents before any implementation, then committed in their own commit (`test: …`).
2. After that commit, `*_acceptance_test.go` and `testdata/acceptance/**` are locked. Implementers must not edit, rename, delete or skip them, add build tags to them, or change helpers they depend on in ways that weaken them.
3. Each acceptance test must fail on the pre-fix code, unless it is marked `// regression guard` in its doc comment. This is verified by running the suite before implementation starts.
4. Implementers may change pre-existing tests only where the old assertion encodes behaviour this plan changes. Each change is listed in the agent's report.
5. Production code must not reference fixture names or test-only values (e.g. `xz-java`, `smiletime`) to pass a test.
6. Final gate: `git diff <test-commit> -- '*_acceptance_test.go' 'testdata/acceptance'` is empty; `go vet ./...` and `go test -race ./...` pass; reviewers confirm no special-casing.

## Work breakdown

- [x] **Tests first:** test agents write the acceptance tests, a critic checks coverage against this plan, and the suite is run on the pre-fix code to confirm it fails.
- [x] **Dependency audit:** choose and pin a YAML library (dependency-auditor; decision record in `docs/decisions/`).
- [x] **Lock:** commit the tests and record the commit hash below.
- [ ] **Implement, wave 1 (parallel, worktrees):** verdict + models + output + sweep (R2 R4 R8); client retry (R11); parsers (R3 R12).
- [ ] **Integrate:** merge wave 1 and run the full suite.
- [ ] **Implement, wave 2:** check command, infer, ecosystem, latest, Maven fallback (R1 R5 R6 R7 R9 R10).
- [ ] **Review:** code-reviewer, security-engineer, and a test-engineer anti-cheat audit.
- [x] **Docs:** docs-writer (R13).
- [ ] **Final gate:** anti-cheat rule 6, then commit.

Locked test commit: `c391888` (54 red, 15 regression guards).

YAML dependency: `go.yaml.in/yaml/v3 v3.0.5`, approved by the user 2026-10-25 (decision 0001). Every manifest and lockfile read goes through `readManifest` (`internal/parser/read.go`): regular files only, capped at 64 MiB. YAML is parsed into a node tree first (`internal/parser/yaml.go`). Aliases are rejected, and only the parts the parser reads are decoded into typed structs, under `recover()` and a cap on yaml.v3's quadratic duplicate-key checking. The yarn berry top level is walked, not decoded. `internal/parser/hostile_test.go` covers the cap, symlinks, alias bombs, deep nesting and wide mappings.
