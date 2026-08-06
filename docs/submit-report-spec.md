# `osm submit` — Feature Spec

## Purpose

Add a command that files a threat report to the OpenSourceMalware.com **`POST /submit-threat-report`**
endpoint (free tier). It gives three ways to compose a report — a text/markdown template file, a
structured JSON object, or a guided interactive prompt — all converging on one validated,
defanged, preview-then-confirm submission.

Working command name: **`osm submit`** (matches the existing one-word verbs `check` / `sweep` /
`latest`). See [open questions](#open-questions) if `submit-report` is preferred.

> **API contract verified** against the official docs (`docs.opensourcemalware.com`, per-endpoint
> pages) on 2026-07-12. The internal `docs/osm-api-guide.md` was **wrong** on the path (it said
> `/submit-threat`) and on two field details — corrections are baked into this spec and flagged
> inline. See [API mapping](#api-mapping).

## Where it fits

- **First write/mutating command.** `check`, `sweep`, and `latest` are all read-only `GET`s. This
  is the first `POST`, so the guardrails (preview, explicit confirm, dry-run) matter more than for
  the read commands.
- **Reuses existing plumbing — nothing new is invented:**
  - Auth/token: already resolved into `appDeps` (`--token` → `OSM_API_KEY` → `~/.osm/config.json`).
    Use `deps.apiClient()` / `deps.requireToken()` exactly like `latest`.
  - Base URL + rate limiter + HTTP client: shared via `appDeps`.
  - Errors: return typed `osmerr` values; `main` owns exit codes.
  - TTY detection: the `term.IsTerminal` pattern already in `cmd/config.go` (but read wizard
    *content* through an injectable seam — see [Architecture](#architecture) S9).
  - Type vocabulary: `report_type` ∈ `package|container|repository|url|domain|ip|wallet` (confirmed
    against the live docs). As with `check`, the CLI keeps `docker` as the user-facing alias and
    maps `docker → container` at the client boundary — reuse `client`'s existing `reportType()`
    helper for that one translation. **Caveat:** this 7-value set is *broader* than the CLI's
    existing check-type vocabulary in `internal/infer` (`package|domain|ip|docker` only), so submit
    does **not** reuse `infer.IsSupported` for validation — that would wrongly reject `repository`,
    `url`, and `wallet`. Define a dedicated 7-value enum + `IsValid` in the new `internal/report`
    package (mirroring how `internal/ecosystem` owns its vocabulary). `infer` is inference-from-a-
    bare-string, which submit doesn't need — the type is stated explicitly in every input mode.
- **Free endpoint.** `POST /submit-threat-report` (and `PUT /modify-threat-report`) are free tier.
  Note two free-tier submission caps: **new users are limited to 3 reports until verified** (403),
  and **10 submissions/hour** (a 429 variant) — see [Errors](#errors--exit-codes).

## Command shape

```
osm submit [FILE] [flags]
```

Exactly one **input mode** per invocation; strictly mutually exclusive (see B1 below):

| Mode | Selector | Input |
| --- | --- | --- |
| **Template file** | positional `FILE` (default) | plaintext/markdown file following the report template |
| **JSON** | `--from-json FILE` (`-` = stdin) | a structured report object |
| **Interactive** | `-i` / `--interactive` | guided prompts, no file needed |

Flags:

| Flag | Effect |
| --- | --- |
| `-i`, `--interactive` | compose through guided prompts |
| `--from-json FILE` | read a structured JSON report (`-` = stdin) |
| `--no-defang` | skip IOC defanging (on by default) |
| `--dry-run` | run the **strictly local** pipeline (collect, validate, defang, preview) — **skips dedupe and submit; zero network** |
| `-y`, `--yes` | assume "yes" to every y/n prompt (final confirm, defang, per-optional-field nudges). Required in non-TTY/CI runs |
| `--emit-json` | **terminal:** print the fully collected/validated/defanged report to stdout and exit 0 — never submits |
| `--template` | **terminal:** print the blank canonical template to stdout and exit 0 |

`--from-json` is chosen over `--json` deliberately: it names an *input source*, distinct from
`sweep`'s `-o json` *output* format.

**Selector precedence & conflicts (resolved):**
- **`--template` and `--emit-json` are top-precedence terminal actions.** `--template` short-circuits
  everything (prints and exits). `--emit-json` runs the local pipeline through defang, prints the
  assembled report, then exits **without submitting**. Combining either with an input mode is
  allowed (they act on/ignore it), but combining `--template` with `--emit-json` is a usage error.
- **The three input modes are strictly mutually exclusive.** Passing more than one input selector
  (`-i` + `--from-json`, positional `FILE` + `--from-json`, `FILE` + `-i`, etc.) is a usage error.
  Pre-filling interactive from a partial file/JSON is **deferred to v2** (see Deferred).
- **Bare `osm submit`** (no FILE, no `-i`, no `--from-json`) → usage error listing the three modes.
- **`--from-json -` and `-i` both want stdin** — since they're mutually exclusive this can't collide.

## Pipeline (shared by all three modes)

```
collect  →  validate  →  defang (default on)  →  dedupe (check-malicious)  →  preview  →  confirm  →  submit  →  result
 (mode)      (shared) -------------------------------------------------------------------------------------------------->
                                    └─ --dry-run / --emit-json stop before dedupe (strictly local) ─┘
```

1. **Collect** — mode-specific (below) → in-memory report struct.
2. **Validate** — required fields missing → `osmerr.Usagef` (exit 2). Optional missing → warn to
   stderr, continue. `report_type` is required *and* enum-checked against the new `report`
   package's 7-value enum (not `infer.IsSupported`; invalid value → usage error); this is
   structural validation, not content/style judgement (which we deliberately do not do). If
   `registry` is supplied, warn (not fail) on an unrecognized value via the existing
   `ecosystem.IsValid` — reuse that vocabulary rather than inventing a second one. Likewise
   warn-only on a malformed `severity_level` (enum `critical|high|medium|low`) or a non-ISO-8601
   `first_seen`/`last_seen` (N4) — surface, don't block.
3. **Defang** — on by default; `Y/n` in interactive mode, `--no-defang` elsewhere. Rewrites IOC
   tokens in **`payload_description` only** and shows a before/after diff on stderr (see
   [Defanging](#defanging)). **Evidence references and `osv_advisory_url` are never defanged** —
   they are citations meant to be followed (B4).
4. **Dedupe** — reuse the existing `check-malicious` client call on `resource_identifier` before
   submitting; if it's already a known/verified threat, warn (and name the `threat_id`) so the
   operator can avoid a duplicate. Non-fatal — a failed check never blocks; the API's duplicate
   rejection is the real backstop. **Skipped entirely by `--dry-run` and `--emit-json`** (they are
   strictly local). This is the one dedupe `GET` that runs before the confirm prompt on a real run;
   it transmits only `resource_identifier`, never the report body.
5. **Preview** — render the exact payload (token/Authorization **redacted**).
6. **Confirm** — require explicit `y` unless `--yes`. **Non-TTY guard:** if stdin is not a terminal
   and `--yes` is absent (and this isn't `--dry-run`/`--emit-json`/`--template`), return
   `osmerr.Usagef` telling the user to pass `-y` — don't hang on a prompt CI can't answer (S1).
   `--dry-run` stops here, zero network.
7. **Submit** — `POST /submit-threat-report` via a new `client` method, under `cmd.Context()`
   (already signal-cancellable) and the shared rate limiter.
8. **Result** — on success (`201`) print the returned `threat_id` + `status` (`pending`) to stdout;
   the response also carries a `message`. On failure map the API error (see
   [Errors](#errors--exit-codes)). If Ctrl-C lands *during* the POST (N8), print a one-line
   "interrupted during submit — the report may or may not have been filed; verify with
   `osm check`/`osm latest`" so the user isn't misled.

**Safety invariant:** no *report* is submitted before step 7, and Ctrl-C anywhere up to and
including the confirm prompt is a clean abort. A non-dry-run does one dedupe `GET` (step 4) before
confirm; `--dry-run`/`--emit-json` do **zero** network.

## Input modes

### Template file (default)

`osm submit --template` prints the canonical blank template so the file *is* the good-report
structure. Missing optional sections surface as validation warnings.

```markdown
# <title / one-line summary>

- Type: package            # report_type (required; `docker` alias → container)
- Resource: axios          # resource_identifier (required)
- Package name: axios      # package_name (optional; distinct from Resource for package reports)
- Registry: npm            # registry  (⚠ NOT `ecosystem` — that's a check/query param, not a submit field)
- Publisher: <name>        # publisher
- Contact: you@example.com # contact_email (optional)
- Affected versions: 1.2.3, 1.2.4   # version_info (comma-separated string)
- Severity: high           # severity_level (critical|high|medium|low)
- First seen: 2026-06-01T00:00:00Z   # first_seen (ISO 8601)
- Last seen: 2026-06-20T00:00:00Z    # last_seen  (ISO 8601)
- Tags: postinstall, exfil # tags (array)
- OSV: <advisory url>      # osv_advisory_url (never defanged)

## Description
<clear explanation of the malicious behavior>   # threat_description (required)

## Payload / IOCs
<markdown; hosts, URLs, IPs — will be defanged>  # payload_description (the only defanged field)

## Evidence
- <url>                    # evidence_references — one per line here; joined to a single
                           #   pipe-delimited string at the API boundary (see API mapping). Never defanged.
```

`contributors` and `download_count` are additional documented optional fields; expose them in JSON
mode and defer richer template affordances (see Deferred).

### JSON (`--from-json`)

An object keyed by API field names, mapped onto the request with light normalization (comma-string
vs array for `version_info`/`tags`; list-vs-pipe-string for `evidence_references`). Non-interactive,
scriptable, CI-friendly. Same validation and defang as every mode. `--from-json -` reads stdin.
**Unknown/misspelled keys are rejected** with a usage error listing accepted keys
(`json.Decoder.DisallowUnknownFields`) so a typo like `serverity_level` fails loudly instead of
silently dropping data (S7).

### Interactive (`-i`)

A **copy-paste-first** wizard. Prompts walk the fields in report order and accept pasted multi-line
input (Description, Payload, Evidence). **Multi-line fields terminate on EOF (Ctrl-D) or a lone
sentinel line (`.`)** — a blank line does *not* end input, since markdown descriptions contain
blank lines; the terminator is echoed in the prompt (S4). Hints are **structural only** ("add a
second evidence URL", "which versions?") — never content/style critique.

**Every prompt must be answerable without the API docs open.** Each prompt spans two or three lines
so a long enum never overflows the terminal: the field name and `(required)`/`(optional)` sit on the
first line; the accepted vocabulary or a short example goes on an indented second line; the answer is
typed after a `> ` marker, with any **default pre-shown on that input line** so pressing Enter
accepts what's displayed (or skips an optional field):

```
report_type (required)
  package|container|repository|url|domain|ip|wallet
> package
resource_identifier (required)
  what you're reporting, e.g. @acme/utils
> 
registry (optional)
  npm|pypi|maven|nuget|rubygems|packagist|crates|go
> npm
first_seen (optional)
  YYYY-MM-DD
> 2026-07-16
```

- **Defaults:** `report_type` → `package`, `registry` → `npm` (the common case), `first_seen` →
  today's date in `YYYY-MM-DD`. Dates use the date-only `YYYY-MM-DD` form (still valid ISO 8601; the
  validator accepts both that and a full RFC 3339 timestamp). Enum vocabularies are rendered from the
  canonical sources (`report.IsValidType`, `ecosystem.All()`) so a new ecosystem shows up in the
  prompt without a second edit.
- **Report-type-aware:** the type is the first prompt and later prompts adapt to it. The `npm`
  registry default applies **only to package reports** — a domain or wallet report has no registry,
  so pre-filling one there would invite a wrong answer rather than save a keystroke.
- **Inline re-prompt** on a blank required field or an invalid `report_type`, rather than deferring
  to the final `Validate` — a typo should cost one line, not the whole wizard. Warn-only fields
  (`registry`, `severity_level`, dates) still fall through to `Validate`'s warnings, matching the
  other input modes.
- **Multi-line blocks carry a worked example** of a usable answer (Description, Payload, Evidence).
  These are the fields people stall on; showing the shape is the difference between a report OSM can
  act on and three lines of shrug.
- **Evidence lines strip a leading `- ` bullet**, since the template writes evidence as a markdown
  list and people reach for the same shape at the prompt.

- **Non-TTY guard:** `-i` requires an interactive stdin. Piped/CI stdin → `osmerr.Usagef` (exit 2)
  suggesting `--from-json -`.
- **`-i` with `-y`:** still prompt for field *content* (required free-text can't be auto-filled),
  but auto-accept the defang `Y/n`, the per-optional-field "add this?" nudges, and the final
  confirm (S3).

## API mapping

`POST {baseURL}/submit-threat-report` (baseURL from `appDeps`), `Authorization: Bearer <token>`,
`Content-Type: application/json`. **Field names below are confirmed against the official docs**
(`api/submit-threat.md`), including the three corrections that differ from `docs/osm-api-guide.md`.

| Report field | Source | Type / notes | Required |
| --- | --- | --- | --- |
| `report_type` | Type (`docker`→`container` at boundary) | 7-value enum | ✅ |
| `resource_identifier` | Resource | string | ✅ |
| `threat_description` | Description | string | ✅ |
| `package_name` | Package name | string; distinct from `resource_identifier` | optional |
| `registry` | Registry | ⚠ **was `ecosystem` in our old spec** — the submit body uses `registry` | optional |
| `publisher` | Publisher | string | optional |
| `contact_email` | Contact | string | optional |
| `payload_description` | Payload / IOCs | markdown; **the only defanged field** | optional |
| `severity_level` | Severity | enum `critical\|high\|medium\|low` | optional |
| `evidence_references` | Evidence | ⚠ **single pipe-`\|`-delimited string**, not an array — join the template's one-per-line list before send | optional |
| `version_info` | Affected versions | comma-separated string | optional |
| `first_seen`, `last_seen` | resp. | ISO 8601 strings | optional |
| `osv_advisory_url` | OSV | string; never defanged | optional |
| `tags` | Tags | array | optional |
| `contributors` | (JSON mode) | array | optional |
| `download_count` | (JSON mode) | number | optional |

> **Verified 2026-07-12** against `docs.opensourcemalware.com`. Three corrections vs. the internal
> guide: (1) path is `/submit-threat-report`; (2) `ecosystem` → **`registry`** on the submit body;
> (3) `evidence_references` is a **pipe-delimited string**, not an array. New documented optional
> fields added: `package_name`, `contact_email`, `contributors`, `download_count`.

## Defanging

On by default. Rewrites IOCs in **`payload_description` only** (never evidence/OSV citation URLs —
B4) to the platform convention:

- `.` → `[.]` inside matched tokens (`190.168.0.1` → `190[.]168[.]0[.]1`)
- `https://` → `hxxps://`, `http://` → `hxxp://`

**Pattern-scoped and idempotent** — never a blanket dot-replacement (which would mangle prose and
version strings like `1.2.3`), and never re-defangs an already-defanged token. The token grammar
must be enumerated and table-tested (S5):

- IPv4, with optional `/CIDR` and `:port` (`10.0.0.0/8`, `1.2.3.4:8080`)
- **IPv6**, bracketed or bare (`2001:db8::1`) — has no dots, so it needs explicit handling or it's a
  silent false-negative on a real IOC
- `scheme://host[/path]` URLs
- bare hostnames with a plausible public-suffix TLD
- **email addresses are matched and skipped** (`abuse@evil.com` must not become `abuse@evil[.]com`)

The before/after diff (stderr) is the backstop against over-reach — but note it's only *reviewed*
on an interactive run; on a `-y`/piped run over-reach would be silent, which is why the grammar must
be tight. When nothing matches, print a one-line "no IOCs to defang". `--no-defang` leaves IOCs
verbatim.

**Punctuation handling (hardened after QA):** the defanger peels surrounding prose punctuation
before classifying a token, so IOCs adjacent to punctuation are still neutralized
(`evil.com.` → `evil[.]com.`, `(evil.com)` → `(evil[.]com)`, `10.0.0.1,` → `10[.]0[.]0[.]1,`).
Credentialed URLs (`http://user:pass@host`) are classified as URLs *before* the email skip so they
are defanged, not mistaken for an email. Clock times (`12:34:56`) are excluded from IPv6 matching.

**Known v1 limitations (documented, not silently dropped):** a bracketed IPv6 literal *with a port*
(`[2001:db8::1]:8080`) and multiple IOCs jammed into one whitespace-free token with no surrounding
spaces (`evil.com,good.com`) are not fully neutralized — the interactive before/after diff is the
backstop, and `--no-defang` is unaffected. Tracked for a v2 substitution-based defanger.

## Auth

No new config. Token comes from the existing precedence chain already resolved into `appDeps`:
`--token` → `OSM_API_KEY` → `~/.osm/config.json` (written by `osm config`). Use
`deps.requireToken()`; a missing token returns `osmerr.ErrNoToken` (operational failure — the
established scheme maps auth to exit 1, with the remedy in the message).

## Errors & exit codes

Map documented API responses to actionable `osmerr` values; `main` owns the exit code (the existing
`0 / 1 / 2 / 3` scheme — no sweep gate here, so `3` is unused). Error bodies below are the actual
documented shapes.

| Situation | Handling | Exit |
| --- | --- | --- |
| `201` success | print `threat_id` + `status` (`pending`) + `message` | 0 |
| `--dry-run` / `--template` / `--emit-json` completed | local only | 0 |
| `401` missing/invalid token, network error, `5xx` | operational `osmerr` (body: `Authorization required` / `Invalid API token`) | 1 |
| `403` new-user report cap (**confirmed real** — 3 reports until verified; body has `verified_reports`/`unverified_reports`) | explain the cap and that it lifts once reports are verified | 1 |
| `409` duplicate | parse **`existingThreatId`** (not `threat_id`) from the body and name it; message as "a report for this resource already exists (id X); nothing filed" — which doubles as the safe answer to a timed-out retry (S6) | 1 |
| `429` general IP rate limit **or** the submission cap (**10/hour, free tier** — distinct from the 60 req/min bucket) | surface which cap; **no `Retry-After` header is documented** — do not assume one | 1 |
| missing required field, invalid `report_type`, unknown JSON key, mode conflict, bare invocation, `-i` on non-TTY, confirm on non-TTY without `-y` | `osmerr.Usagef` | 2 |

> The 10/hour submission cap is **not** protected by the shared 30-req/min limiter, so `osm submit`
> must handle that 429 variant with a clear message rather than relying on the limiter (research
> flagged this as its own failure mode).

### stdout / stderr discipline

Already the house pattern (`cmd.OutOrStdout()` / `cmd.ErrOrStderr()`). **stdout carries only
machine output**: `--emit-json`, `--template`, and the final `threat_id`. Prompts, hints, defang
diff, preview, warnings, errors → stderr. Keeps `--emit-json | --from-json` round-trips clean (and
because `--emit-json` prints the *post-defang* report and defang is idempotent, the round-trip is
stable).

## Architecture

- **New cobra command** `cmd/submit.go`: `newSubmitCmd(deps *appDeps)` + `runSubmit(...)`,
  registered in `root.go`. Orchestration only — no business logic in `cmd/` (house rule).
- **New internal package** `internal/report` (or `internal/submit`): the report struct, the three
  mode parsers, the validator, and the defanger — all **pure**, table-tested against fixtures.
  Nothing in `internal/` imports `cmd`.
- **Client extension:** add `SubmitThreat(ctx, req) (Result, error)` to `internal/client`
  (concrete return, consumer-side interface if a command needs to fake it — matching the existing
  client convention). The `docker → container` mapping stays at this boundary, and the request
  struct marshals `evidence_references` as a pipe-delimited string.
- **Dedupe reuses** the existing `check-malicious` client method — no new endpoint needed for the
  pre-submit check. Note (N7): `client.Query.Type`'s comment (`query.go`) lists only
  `package|domain|ip|docker`; dedupe now passes the broader 7-value set through `reportType()`
  (which forwards unknown values unchanged, so it works) — **update that comment** so the wider
  vocabulary doesn't read as a bug to a maintainer.
- **Testability seam (S9):** read wizard *content* via `cmd.InOrStdin()` (injectable) and isolate
  the un-fakeable `term.IsTerminal` check behind a small seam (a `func() bool` field defaulting to
  the real check) so tests can exercise both the non-TTY guard and the interactive transcript.
- **Deps already present** (cobra, term, x/time/rate, BurntSushi/toml) — reuse; add nothing.

## Testing

Test cases are grouped by behavior. Each is written as what we're proving, then the pass condition
and the fail condition it guards against. Client cases run against an `httptest` server via
`OSM_BASE_URL`; pipeline/parser/defanger cases run pure against fixtures.

### Sending a report

- **T1 — A complete report reaches the API and returns an ID.** A valid report submitted with
  confirmation produces exactly one `POST /submit-threat-report` and prints the returned `threat_id`
  and `pending` status. *Fails if:* no request is made, or a `201` comes back but no ID reaches the
  user.
- **T2 — The wire payload is exactly what we assembled.** The captured request body matches the
  previewed report field-for-field, including `registry` (not `ecosystem`) and
  `evidence_references` joined into one pipe-delimited string. *Fails if:* any field is renamed,
  dropped, or the evidence list is sent as an array.

### The safety check before sending

- **T3 — Nothing is sent before the user confirms.** With the confirm prompt declined, zero submit
  requests are made and the command exits cleanly. *Fails if:* any `POST` fires before a `y`.
- **T4 — It refuses to submit blind on a non-TTY.** Piped stdin with no `-y` returns a usage error
  and makes no request, rather than hanging or auto-sending. *Fails if:* it hangs, or it submits
  without a confirmation source.
- **T5 — `-y` is the only thing that auto-confirms.** With `--yes`, the same report submits with no
  prompt. *Fails if:* it still blocks, or if anything other than `-y` skips the confirm.

### The three ways to write a report

- **T6 — All three modes assemble the same report.** The same content via template file,
  `--from-json`, and an interactive transcript produce byte-identical assembled requests. *Fails
  if:* one mode maps a field differently or skips a pipeline step.
- **T7 — Exactly one input mode per run.** Any two selectors together (`FILE + --from-json`,
  `FILE + -i`, `-i + --from-json`) return a usage error. *Fails if:* one combination is silently
  accepted.

### Practice runs (nothing sent)

- **T8 — `--template` prints the blank form and exits without touching the network.** *Fails if:* it
  makes any request.
- **T9 — `--dry-run` and `--emit-json` show the assembled report and make zero requests** — no
  dedupe call, no submit. *Fails if:* either fires a single `GET` or `POST`.
- **T10 — Bare `osm submit` shows usage, sends nothing.** *Fails if:* it guesses a mode or contacts
  the API.

### Catching problems early

- **T11 — Missing required fields block.** Absent `report_type`, `resource_identifier`, or
  `threat_description` → usage error (exit 2), no request. *Fails if:* an incomplete report is sent.
- **T12 — Optional gaps only warn.** A report missing only optional fields warns to stderr and still
  submits. *Fails if:* an optional gap blocks the submit.
- **T13 — Bad values are caught at the right severity.** An invalid `report_type` or an unknown JSON
  key is a usage error; a bad `severity_level` or non-ISO date only warns. *Fails if:* the
  severities are swapped (a typo'd key silently dropped, or a bad date blocks).

### Cleaning up dangerous links

- **T14 — Defang neutralizes live IOCs in the description.** URLs, IPv4, IPv6, hostnames — including
  CIDR and `:port` forms — are rewritten to the platform convention. *Fails if:* any documented IOC
  shape passes through clickable (esp. IPv6, which has no dots).
- **T15 — Defang leaves the wrong things alone.** Prose, version strings like `1.2.3`, email
  addresses, and the evidence/OSV citation URLs are untouched, and re-running defang changes
  nothing. *Fails if:* it mangles a citation, a version, an email, or double-defangs.
- **T16 — `--no-defang` sends IOCs verbatim.** *Fails if:* defang still runs.

### When OSM says no

- **T17 — Each documented rejection gives a plain typed error, not a crash.** `403` (new-user cap),
  `409` (duplicate — naming the `existingThreatId`), and both `429`s (rate limit vs. the 10/hour
  submission cap) each map to a distinct readable `osmerr` and exit 1. *Fails if:* any returns a raw
  status, a stack trace, or the wrong exit code.

### Fitting the rest of the tool

- **T18 — Auth and pacing match the other commands.** A missing token returns `ErrNoToken` (exit 1)
  before any request; submits go through the shared rate limiter. *Fails if:* it needs its own login
  or bypasses the limiter.
- **T19 — Success means success, failure means failure.** A `201` exits 0; a duplicate rejection
  exits 1 but reads as "already exists," not as a tool bug. *Fails if:* a rejected report is
  reported as a crash, or a failure exits 0.

> **Cannot be covered until we test the live API** (out of scope for the `httptest` suite): whether a
> retried submit after a timeout files a duplicate (idempotency), and the exact JSON shape of the
> `409` duplicate body. Tracked as open questions #2 and the `409` parsing detail.

## Deferred / out of scope (v1)

- **Pre-filling interactive from a partial file/JSON** (the `FILE + -i` merge) — kept out to
  preserve strict mode mutual-exclusivity; revisit in v2 with explicit field-level precedence.
- Editing/withdrawing a submitted report (there is a `PUT /modify-threat-report`, free tier, 30/hr
  cap — a natural follow-up `osm modify`, separate feature).
- `--force` past a known dedupe hit (open question #3) — warn-only for v1; the API's 409 is the real
  backstop.
- Batch / multi-report submission.
- In-wizard field re-edit / back-navigation (N2); `$EDITOR` integration (N3); template `FILE = -`
  stdin symmetry (N5); `--type`/`--registry` quick-seed flags (N6). Minor UX, deferred.
- Auto-populating a report from a `sweep` hit (natural future — a detected malicious package could
  seed a pre-filled report into this same pipeline).

## Open questions

1. **Command name:** `osm submit` (matches `check`/`sweep`/`latest`) vs. `osm submit-report`
   (matches how we've been referring to it). Leaning `osm submit`.
2. **Idempotency key:** does `POST /submit-threat-report` honor a client-supplied idempotency key?
   Not documented. If it does, sending one would make timed-out retries safe (S6). Verify before
   relying on it; otherwise the 409-`existingThreatId` handling is the fallback.
3. **Dedupe aggressiveness:** warn-only on a `check-malicious` hit (current lean), or also require
   a `--force` to proceed past a known-duplicate?
