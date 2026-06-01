# `osm` — OpenSourceMalware CLI

## Overview

A Go CLI tool for querying the OpenSourceMalware.com free API. Three commands: `check` (ad-hoc lookup), `sweep` (batch manifest scan for CI gates), and `latest` (fetch recent verified threats by ecosystem).

**Auth:** Bearer token via `OSM_API_KEY` env var, `--token` flag, or saved via `osm config`.  
**Auth precedence:** `--token` flag → `OSM_API_KEY` env var → `~/.osm/config.json`  
**Base URL:** `https://api.opensourcemalware.com/v1`  
**Rate limit:** 60 req/min — token-bucket limiter; sweep responses cached 24h to `~/.osm/cache.json`.

---

## Feature 1: `osm config`

Prompts for the API key and saves it to `~/.osm/config.json`. Run once on setup.

```
osm config
```

---

## Feature 2: `osm check`

Ad-hoc single lookup for a package, domain, IP, or Docker image. Prints a detail block. No caching.

```
osm check express -e npm
osm check express -e npm --version 4.18.2
osm check evil.com
osm check 1.2.3.4
osm check nginx:latest
osm check express -T package -e npm   # explicit type override
```

**Type inference** (applied in order):

```
Input: "1.2.3.4"
  ├── matches IP pattern?       yes → type: ip ✓

Input: "nginx:latest"
  ├── matches IP pattern?       no
  ├── contains : or registry/?  yes → type: docker ✓

Input: "evil.com"
  ├── matches IP pattern?       no
  ├── contains : or registry/?  no
  ├── contains a dot?           yes → type: domain ✓

Input: "express" --ecosystem npm
  ├── matches IP pattern?       no
  ├── contains : or registry/?  no
  ├── contains a dot?           no
  └── default → type: package ✓

Input: "express"  (no --ecosystem)
  ├── matches IP pattern?       no
  ├── contains : or registry/?  no
  ├── contains a dot?           no
  └── default → type: package, but --ecosystem required → error
```

`--type` is available as an explicit override at any step.

**Supported types:** `package`, `domain`, `ip`, `docker`

**Output:** multi-line detail block — name, type, severity, description, tags, first_seen.

---

## Feature 3: `osm sweep`

Batch-checks direct dependencies from a manifest file against `check-malicious`.

```
osm sweep --file package.json
osm sweep --file requirements.txt
osm sweep --file package-lock.json
osm sweep --file poetry.lock
osm sweep --file package.json --fail-on-any    # exit 1 if any hit (CI mode)
osm sweep --file package.json --output json    # JSON array output
```

**Behaviour:**
- Parse input file, extract direct package names + versions
- Deduplicate, then fan out requests with rate limiting
- Print a table: package | version | status | severity | first_seen (all packages shown)
- `--fail-on-any` exits 1 on any `malicious: true` result; exits 0 with summary when clean
- On API unreachable (network error, 5xx): exit 1
- Cache responses per package+version (24h) to `~/.osm/cache.json`

**Supported input formats:**
- `package.json` — direct dependencies only (dependencies + devDependencies)
- `package-lock.json` — direct dependencies only
- `requirements.txt`
- `poetry.lock`

**Output formats:** table (default), JSON array (`--output json`)

---

## Feature 4: `osm latest`

Fetches the 100 most recent verified threats per ecosystem from `query-latest`. One-shot, not a daemon.

```
osm latest                              # all supported ecosystems
osm latest -e npm
osm latest -e pypi
osm latest -e npm,pypi,maven
```

**Supported ecosystems:** `npm`, `pypi`, `maven`, `nuget`, `rubygems`, `packagist`, `crates`, `go`

**Output:** JSON (default)

---

## Project Structure

```
cmd/
  config.go
  check.go
  sweep.go
  latest.go
internal/
  client/      # OSM API client, rate limiter
  cache/       # local file cache (~/.osm/cache.json)
  parser/      # package manifest parsers
  output/      # table, json formatters
main.go
```

## Flags

| Flag | Short | Commands |
|---|---|---|
| `--ecosystem` | `-e` | `check`, `latest` |
| `--file` | `-f` | `sweep` |
| `--output` | `-o` | `sweep` |
| `--token` | `-t` | all |
| `--type` | `-T` | `check` |
| `--version` | — | skip (conflicts with root) |
| `--fail-on-any` | — | `sweep` |

## Dependencies

- `cobra` — CLI framework
- stdlib `net/http` — HTTP client
- Standard library only for cache/config (JSON files, no DB)

## Out of Scope

- `osm watch` (daemon/polling mode) — deferred
- Paid API endpoints (`/threat-feed`, `/threat-data`, STIX)
- Transitive dependency scanning — direct deps only
- Wallets, repositories, containers (other than Docker images)
- Automatic remediation
- Any UI or web component
