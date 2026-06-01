# osm

CLI tool for querying the [OpenSourceMalware.com](https://opensourcemalware.com) API — check packages, domains, and IPs against a community-verified malicious package database.

## Install

```sh
go install github.com/fieldse/osm-tools@latest
```

## Setup

Get a free key at [opensourcemalware.com](https://opensourcemalware.com), then provide it one of three ways:

```sh
osm config                      # prompt + save to ~/.osm/config.json (persists across shells)
export OSM_API_KEY=osm_...       # current shell only
osm check evil.com --token osm_...   # one-off
```

**Auth precedence:** `--token` flag → `OSM_API_KEY` env var → `~/.osm/config.json`

> `osm` does not read `.env` files — set the environment variable yourself or use `osm config`.

## Commands

### `osm check`

Ad-hoc lookup for a package, domain, IP, or Docker image.

```sh
osm check express -e npm
osm check express -e npm --version 4.18.2
osm check evil.com
osm check 1.2.3.4
osm check nginx:latest
osm check express -T package -e npm   # explicit type override
```

Type is inferred from the input: IP pattern → `ip`, contains `:` → `docker`, contains `.` → `domain`, everything else → `package` (requires `-e`).

### `osm sweep`

Batch-checks direct dependencies from a manifest file. Designed for CI gates.

```sh
osm sweep -f package.json
osm sweep -f requirements.txt
osm sweep -f package-lock.json
osm sweep -f poetry.lock
osm sweep -f package.json --fail-on-any   # non-zero exit if any hit (CI gate)
osm sweep -f package.json -o json         # JSON array output
```

Supported formats: `package.json`, `package-lock.json`, `requirements.txt`, `poetry.lock`. Direct dependencies only. Responses cached 24h to `~/.osm/cache.json`.

### `osm latest`

Fetches the 100 most recent verified threats per ecosystem.

```sh
osm latest                   # all ecosystems
osm latest -e npm
osm latest -e npm,pypi,maven
```

Supported ecosystems: `npm`, `pypi`, `maven`, `nuget`, `rubygems`, `packagist`, `crates`, `go`

Output: JSON.

## Flags

| Flag | Short | Commands |
|---|---|---|
| `--ecosystem` | `-e` | `check`, `latest` |
| `--file` | `-f` | `sweep` |
| `--output` | `-o` | `sweep` |
| `--token` | `-t` | all |
| `--type` | `-T` | `check` |
| `--fail-on-any` | — | `sweep` |
