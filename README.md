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

**Lookup type** is chosen in this order:
1. `-T` if given: `package`, `domain`, `ip` or `docker`.
2. `-e` makes it a package lookup.
3. Otherwise it is inferred from the input. IPs, domains and Docker images (a `:` tag or a known registry such as `ghcr.io/`) are detected; anything else is a package.

A package lookup needs `-e`. Without it, `check` exits 2. An image name with no tag and no known registry prefix, such as `aquasec/trivy`, is read as a package, so pass `-T docker`.

Repositories, URLs and wallet addresses are not supported. `check` rejects them with exit 2 before sending any request, including when passed as `-T repository`, `-T url` or `-T wallet`. See [supported asset types](https://docs.opensourcemalware.com/asset-types).

Domains are lowercased before lookup. Package names are sent exactly as typed.

**Verdicts:**
- `MALICIOUS`: a hit that covers every version, or a hit on the exact `--version` you passed.
- `REVIEW`: a hit on specific versions when no exact version was given, a warning that the package has known malicious versions, or a Maven hit found only by its bare artifactId.
- `CLEAN`: anything else, usually no record in the database.

The output lists the affected versions and the OSM page URL when the API returns them. `check` exits 0 for all three verdicts.

For Maven, give `groupId:artifactId`. If that comes back clean, `check` retries once with the bare artifactId, because OSM stores some Maven records that way. A hit from the retry is reported as `REVIEW`, since the artifactId may belong to a different groupId. A full coordinate with a version (`groupId:artifactId:version`, optionally with packaging and classifier) that comes back clean is first retried as `groupId:artifactId` at that version, unless `--version` is set, and then with the bare artifactId.

> **Package names must match the registry exactly.** A clean result means "not in the database," not "verified safe." A typo'd or unscoped name will silently appear clean.

### `osm sweep`

Batch-checks direct dependencies from a manifest. Designed for CI gates.

```sh
osm sweep -f package.json
osm sweep -f requirements.txt
osm sweep -f package-lock.json
osm sweep -f poetry.lock
osm sweep -f pnpm-lock.yaml
osm sweep -f yarn.lock                    # needs package.json in the same directory
osm sweep -f package.json --fail-on-any   # exit 3 on any MALICIOUS or REVIEW row
osm sweep -f package.json -o json         # JSON output
```

Supported manifests:
- `package.json`
- `package-lock.json`
- `pnpm-lock.yaml` (lockfile v6 and v9; monorepos check every project's direct deps)
- `yarn.lock` (v1 and berry)
- `requirements.txt`
- `poetry.lock`

Sweep checks direct dependencies. For npm manifests that means `dependencies`, `devDependencies` and `optionalDependencies`. `yarn.lock` cannot tell direct deps from transitive ones, so sweep reads the `package.json` beside it. If that file is missing, sweep exits 1. Two formats check every locked package, transitive ones included: `poetry.lock` and v1 `package-lock.json`.

For npm manifests, only exact versions are sent. A range such as `^1.14.0` is looked up with no version, and a hit on specific versions then shows as `REVIEW`. Local and git dependencies (`workspace:`, `file:`, `link:`, git and tarball URLs) are skipped. In `requirements.txt`, a version is sent for any `==` pin, including wildcard pins such as `==1.0.*`. The verdict still treats those as non-exact.

Each row shows the package, version, verdict (`MALICIOUS`, `REVIEW` or `CLEAN`, as for `check`), severity and affected versions. JSON rows also carry `osm_url` when present.

Results are cached for 24 hours in `~/.osm/cache.json`.

### `osm latest`

Returns the 100 most recent verified threats per ecosystem.

```sh
osm latest                      # all ecosystems
osm latest -e npm
osm latest -e npm,pypi,maven
```

Supported ecosystems: `npm`, `pypi`, `maven`, `nuget`, `rubygems`, `packagist`, `crates`, `go`, `vscode`, `openvsx`, `skills`, `brew`. Names are lowercase; an unknown name exits 2. The same list applies to `check -e`.

### `osm submit`

Files a threat report to OpenSourceMalware.com. Compose it from a template file, a JSON file, or an interactive wizard; every run previews the report and waits for confirmation before sending.

```sh
osm submit report.md                          # template file
osm submit --from-json report.json            # structured JSON
osm submit -i                                 # interactive wizard
osm submit report.md --dry-run                # rehearse — no network
osm submit report.md --emit-json              # print assembled JSON, no network
osm submit --template > report.md             # write a blank template
```

See the [submit guide](docs/submit.md) for copy-paste examples of each mode, defanging, CI usage, and exit codes.

### Flags

| Flag | Short | Commands | Description |
|---|---|---|---|
| `--token` | `-t` | all | API key |
| `--ecosystem` | `-e` | `check`, `latest` | Package ecosystem (e.g. `npm`, `pypi`); on `check`, makes it a package lookup |
| `--type` | `-T` | `check` | Asset type override (`package`, `domain`, `ip`, `docker`) |
| `--version` | | `check` | Package version |
| `--debug` | | `check` | Print the API request and response status to stderr |
| `--file` | `-f` | `sweep` | Manifest file path |
| `--output` | `-o` | `sweep` | Output format (`json`) |
| `--fail-on-any` | | `sweep` | Exit 3 if any row is `MALICIOUS` or `REVIEW` |
| `--interactive` | `-i` | `submit` | Compose the report through guided prompts |
| `--from-json` | | `submit` | Read a structured JSON report (`-` = stdin) |
| `--template` | | `submit` | Print the blank report template and exit |
| `--emit-json` | | `submit` | Print the assembled report as JSON and exit |
| `--dry-run` | | `submit` | Run the local pipeline, stop before submit |
| `--no-defang` | | `submit` | Send IOCs verbatim instead of neutralizing them |
| `--yes` | `-y` | `submit` | Assume yes to prompts; required in non-TTY runs |

### Rate limits

The free tier allows 60 requests per minute and 2000 per day. `osm` paces itself at 30 requests per minute, so a large manifest takes a while to sweep.

If the API returns a per-minute 429, `osm` waits and retries, up to 3 times. The wait is the `Retry-After` time capped at 60 seconds, or 2 seconds if the header is missing. A daily-quota 429 is not retried, and the command exits 1.

### Exit codes

`check`, `sweep` and `latest` use these codes. `submit` has its own; see the [submit guide](docs/submit.md#exit-codes).

| Code | Meaning |
|---|---|
| 0 | Success, whatever the verdict |
| 1 | Operational error: network, auth, API error, unreadable or malformed manifest |
| 2 | Usage error: bad flag, unknown ecosystem or manifest, unsupported asset type |
| 3 | `sweep --fail-on-any` found a `MALICIOUS` or `REVIEW` row |

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
