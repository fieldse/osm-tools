# osm

CLI for the [OpenSourceMalware.com](https://opensourcemalware.com) API — check packages, domains, IPs, and Docker images against a community-verified malicious package database.

---

## Install

```sh
go install github.com/fieldse/osm-tools@latest
```

## Setup

Get an API key at [opensourcemalware.com](https://opensourcemalware.com), then provide it one of three ways:

```sh
osm config                              # prompt + save to ~/.osm/config.json
export OSM_API_KEY=osm_...              # current shell only
osm check evil.com --token osm_...      # one-off
```

---

## Commands

### `osm check`

Ad-hoc lookup for a package, domain, IP, or Docker image.

```sh
osm check express -e npm
osm check express -e npm --version 4.18.2
osm check @scope/pkg -e npm           # scoped npm — include the full @scope/name
osm check evil.com
osm check 1.2.3.4
osm check nginx:latest
osm check express -T package -e npm   # explicit type override
```

**Types:** Inferred from the input — IPs, domains, and Docker images are detected automatically; anything else is treated as a package. Use `-T` to be explicit: `package`, `domain`, `ip`, `docker`. See [supported asset types](https://docs.opensourcemalware.com/asset-types).

> **Package names must match the registry exactly.** A clean result means "not in the database," not "verified safe." A typo'd or unscoped name will silently appear clean.

### `osm sweep`

Batch-checks direct dependencies from a manifest. Designed for CI gates.

```sh
osm sweep -f package.json
osm sweep -f requirements.txt
osm sweep -f package-lock.json
osm sweep -f poetry.lock
osm sweep -f package.json --fail-on-any   # exit 3 on any hit
osm sweep -f package.json -o json         # JSON output
```

Supported manifests: `package.json`, `package-lock.json`, `requirements.txt`, `poetry.lock`. Direct dependencies only.

Requests are paced at 30/min (half the API ceiling) — large manifests will take a moment.

### `osm latest`

Returns the 100 most recent verified threats per ecosystem.

```sh
osm latest                      # all ecosystems
osm latest -e npm
osm latest -e npm,pypi,maven
```

Supported ecosystems: `npm`, `pypi`, `maven`, `nuget`, `rubygems`, `packagist`, `crates`, `go` — [full list](https://docs.opensourcemalware.com/asset-types)

### Flags

| Flag | Short | Commands | Description |
|---|---|---|---|
| `--token` | `-t` | all | API key |
| `--ecosystem` | `-e` | `check`, `latest` | Package ecosystem (e.g. `npm`, `pypi`) |
| `--type` | `-T` | `check` | Asset type override (`package`, `domain`, `ip`, `docker`) |
| `--version` | | `check` | Package version |
| `--file` | `-f` | `sweep` | Manifest file path |
| `--output` | `-o` | `sweep` | Output format (`json`) |
| `--fail-on-any` | | `sweep` | Exit 3 if any malicious hit |

---

## Development

```sh
make build    # compile to bin/osm
make test     # run tests
make clean    # remove bin/
```

Also: `make test-race`, `make integration`, `make vet`, `make fmt`, `make lint`.

---

## About OpenSourceMalware.com

[OpenSourceMalware.com](https://opensourcemalware.com) is a community threat-intelligence platform for tracking malicious open-source software. Security professionals submit verified reports; a four-stage review process keeps data quality high. Coverage spans npm, PyPI, Maven, NuGet, RubyGems, crates.io, Go Modules, Docker, and more.

If you find a malicious package, [report it](https://opensourcemalware.com/report) — see the [reporting guidelines](https://docs.opensourcemalware.com/reporting/guidelines) for what to include.
