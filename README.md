# osm

CLI for the [OpenSourceMalware.com](https://opensourcemalware.com) API — check packages, domains, IPs, and Docker images against a community-verified malicious package database.

## What it does and doesn't do

`osm` looks up names in OSM's database of confirmed malware: packages that were malicious from the start, or real packages whose maintainer account was taken over.

- **It finds** packages, domains, IPs and container images that OSM has verified as malicious.
- **It does not find** ordinary security bugs (CVEs). Use a vulnerability scanner such as Grype or OSV-Scanner for those.
- **It does not analyse code.** It only matches names, and versions where OSM lists them.
- **`CLEAN` means "no record found",** not "safe". A misspelled name also comes back `CLEAN`.

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
osm check aquasec/trivy -T docker     # untagged image
```

**Packages** need `-e` with the package's ecosystem: the registry it is published on. Type the name exactly as that registry does: case, `@scope/` and separators all matter.

| `-e` value | Registry |
|---|---|
| `npm` | npm (JavaScript) |
| `pypi` | PyPI (Python) |
| `maven` | Maven Central (Java) |
| `nuget` | NuGet (.NET) |
| `rubygems` | RubyGems (Ruby) |
| `packagist` | Packagist (PHP) |
| `crates` | crates.io (Rust) |
| `go` | Go modules |
| `vscode` | VS Code Marketplace extensions |
| `openvsx` | Open VSX extensions |
| `skills` | AI agent skill registries |
| `brew` | Homebrew |

**Domains, IPs and images** need no flag; `osm` detects them. An image with no tag, such as `aquasec/trivy`, needs `-T docker`.

Repositories, URLs and wallet addresses are not supported.

**Name formats** that trip people up:

| Ecosystem | Write it as | Won't match |
|---|---|---|
| npm | `@scope/name` | `scope/name` |
| pypi | the registry's exact spelling (`tns-py`) | `TNS-PY`, `tns_py` |
| maven | `groupId:artifactId` | (see Maven below) |
| go | full module path; versions with `v` (`v0.1.0`) | `0.1.0` |
| nuget, vscode | exact case (`Zendesk.OAuth`) | `zendesk.oauth` |

**Maven:** write the name as `groupId:artifactId`. OSM stores some Maven records under the artifactId alone, so `osm` also checks that. A match found that way shows as `REVIEW`: check the groupId before trusting it.

**Verdicts:**
- `MALICIOUS`: a hit that covers every version, or a hit on the exact `--version` you passed.
- `REVIEW`: a hit on specific versions when no exact version was given, a warning that the package has known malicious versions, or a Maven hit found only by its bare artifactId.
- `CLEAN`: anything else, usually no record in the database.

The output lists the affected versions and the OSM page URL when the API returns them. `check` exits 0 for all three verdicts.

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

`-e` takes the same values as `check` (see the table under [`osm check`](#osm-check)). An unknown value exits 2.

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
