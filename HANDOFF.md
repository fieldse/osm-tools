# HANDOFF — `osm submit` (submit-report) feature

**Date:** 2026-07-12
**Status:** Design complete, not yet implemented.
**Spec:** [`docs/submit-report-spec.md`](docs/submit-report-spec.md)

## What we're doing

Adding a command to file a threat report to OpenSourceMalware.com's free
`POST /submit-threat` endpoint. This is the tool's **first write command** — everything today
(`check`, `sweep`, `latest`) is read-only — so it carries extra guardrails (preview → explicit
confirm → dry-run) before anything is sent.

Three ways to compose a report, all converging on one shared pipeline
(collect → validate → defang → dedupe → preview → confirm → submit):

1. **Template file** — `osm submit <file>` (plaintext/markdown; `osm submit --template` prints the blank form).
2. **Structured JSON** — `osm submit --from-json <file|->`.
3. **Guided interactive** — `osm submit -i` (copy-paste-first, structural hints only).

## Decisions already locked (don't relitigate)

- **Only required fields block** (`report_type`, `resource_identifier`, `threat_description`);
  missing optional fields only warn. No content/style linting. Interactive mode adds a `y/n`
  "add this?" nudge per blank optional field.
- **Defang on by default**, `--no-defang` to skip. Pattern-scoped (URL/IP/hostname tokens only,
  idempotent — NOT a blanket `.`→`[.]`), full convention (`.`→`[.]`, `https`→`hxxps`), shown as a
  diff before submit.
- **No new config/auth** — reuse the existing `appDeps` token chain (`--token` → `OSM_API_KEY` →
  `~/.osm/config.json`) and rate limiter.
- **Fits existing conventions:** new cobra command in `cmd/submit.go` (orchestration only); pure
  logic in a new `internal/` package; typed `osmerr` errors with `main` owning exit codes
  (0 ok · 1 operational · 2 usage); `docker → container` mapping at the client boundary;
  stdout = machine output only.

## Why this handoff exists

This feature was initially, mistakenly designed against the **wrong repository** — the `fragcheck`
kernel-CVE auditor, which shares the `github.com/fieldse/...` namespace and confusingly similar
docs. The design has been re-grounded against **this** project's real conventions (cobra + DI via
`appDeps`, `~/.osm/config.json`, the `0/1/2/3` exit scheme, `osmerr`, the shared rate limiter) and
moved here. The stray spec left in the fragcheck repo has been removed.

## Open questions before coding

1. **Command name:** `osm submit` (matches `check`/`sweep`/`latest`) vs `osm submit-report`. Leaning `osm submit`.
2. **Endpoint + field names:** `docs/osm-api-guide.md` says `/submit-threat`; the public docs page
   says `/submit-threat-report`. **Verify against the live API before implementing** — likewise the
   exact optional-field names.
3. **Dedupe strength:** warn-only on a `check-malicious` hit (current lean) vs require `--force` to
   proceed past a known duplicate.

## Suggested next steps

1. Confirm the three open questions above (esp. the live endpoint path + field names).
2. Extend `internal/client` with `SubmitThreat(ctx, req)` + request/response types; test against an
   `httptest` server via `OSM_BASE_URL`.
3. Build the pure `internal/` report package (struct, three parsers, validator, defanger) with
   golden fixtures.
4. Wire `cmd/submit.go` and register it in `root.go`.
5. Update `README.md` and `CLAUDE.md` (command list) once landed.
