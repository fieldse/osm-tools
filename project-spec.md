# `osm` — OpenSourceMalware CLI

## Overview

A Go CLI tool for querying the OpenSourceMalware.com free API. Two core features: dependency sweep for CI gates and a watch/diff daemon for ambient feed monitoring.

**Auth:** Bearer token via `OSM_API_KEY` env var or `--token` flag.  
**Base URL:** `https://api.opensourcemalware.com/v1`  
**Rate limit:** 60 req/min — implement a token-bucket limiter and response cache (24h TTL, local file).

---

## Feature 1: `osm sweep`

Batch-checks direct dependencies against `check-malicious`.

```
osm sweep --file package.json
osm sweep --file requirements.txt
osm sweep --ecosystem npm --file package-lock.json
osm sweep --fail-on-any          # exit 1 if any hit (CI mode)
osm sweep --output json          # structured output for downstream tooling
```

**Behaviour:**
- Parse input file, extract package names + versions
- Deduplicate, then fan out requests with rate limiting
- Print a table: package | version | status | severity | first_seen
- `--fail-on-any` sets exit code 1 on any `malicious: true` result
- Cache responses per package+version (24h) to a local `~/.osm/cache.json`

**Supported input formats:**
- `package.json` (dependencies + devDependencies)
- `package-lock.json` (includes transitive deps)
- `requirements.txt`
- `poetry.lock`

---

## Feature 2: `osm watch`

Polls `query-latest` per ecosystem on a schedule, diffs against local state, emits only net-new threats.

```
osm watch --ecosystem npm,pypi
osm watch --ecosystem npm --interval 1h
osm watch --webhook https://hooks.slack.com/...   # POST new hits to Slack
osm watch --output jsonl                          # append to file for ingestion
```

**Behaviour:**
- On each tick, fetch `query-latest` for each configured ecosystem
- Load last-seen state from `~/.osm/watch-state.json` (keyed by `threat_id`)
- Diff: emit only entries not previously seen
- Write updated state back to disk
- If `--webhook` set, POST each new hit as a minimal Slack-compatible JSON payload
- If `--output jsonl` set, append each new hit as a JSON line to a file

**Output fields per hit:** `ecosystem`, `package`, `version`, `severity`, `description`, `tags`, `first_seen`, `threat_id`

---

## Feature 3: `osm check` (bonus, lightweight)

Ad-hoc single lookup for use during code review or incident response.

```
osm check npm express
osm check pypi litellm 1.82.7
osm check domain models.litellm.cloud
```

Prints a single-line result or a short detail block. No caching.

---

## Project Structure

```
cmd/
  sweep.go
  watch.go
  check.go
internal/
  client/      # OSM API client, rate limiter
  cache/       # local file cache
  parser/      # package manifest parsers
  output/      # table, json, jsonl formatters
main.go
```

## Dependencies (suggested)

- `cobra` — CLI framework
- `resty` or stdlib `net/http` — HTTP client
- Standard library only for cache/state (JSON files, no DB)

## Out of Scope

- Paid API endpoints (`/threat-feed`, `/threat-data`, STIX)
- Any UI or web component
- Automatic remediation
