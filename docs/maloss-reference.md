# MALOSS — Reference

## Purpose
CLI tool that scans dependency manifests to detect **known-malicious open-source packages** (not general CVEs). Fills the gap that traditional SCA tools miss — they flag vulnerable versions but not packages that are outright malware. Designed for manual use and CI/CD pipelines (exit `1` on findings, `0` when clean).

## Repo Layout
- **`maloss.py`** — original Python implementation (~970 lines). Deps: `requests`, `beautifulsoup4`, `tomli`.
- **`npm/maloss.js`** — JavaScript port (~1188 lines), published to npm as `maloss` v0.2.3. **Zero runtime deps** (built-in `https`/`http`, hand-rolled TOML + regex HTML parsing).
- **`tests/`** — paired `clean/` vs `malicious/` fixtures for each manifest type; `test-everything.sh` is a manual smoke test (⚠️ has a hardcoded author-specific `WORKDIR`).
- Author: "6mile" (Paul McCarty). License ISC. Repo: `github.com/6mile/MALOSS`.

> **Key fact for any code work:** the program is implemented *twice* (Python + JS), mirrored class-for-class. Any parser/logic change must be applied to **both** files to keep them in sync.

## Core Pipeline (identical in both languages)
1. **`PackageParser`** — detects file by name, extracts `(name, version)`. Supports `package.json`, `package-lock.json` (v1 + v2/v3), `pyproject.toml` (PEP 621 + Poetry), `requirements.txt`.
2. **`RemoteFileDownloader`** — `--remote` converts GitHub/GitLab blob URLs → raw, downloads to `/tmp/maloss/`.
3. **`VulnerabilityChecker`** — checks each package against two sources (below).
4. **`SecurityScanner`** — orchestrates; `generate_report` emits human-readable (colored/emoji) or `--json`, to console or `--output` file.

## Data Sources
- **OSV API** (`api.osv.dev/v1/query`) — POST per package (name + ecosystem npm/PyPI). Keeps **only `MAL-` prefixed advisories**, drops CVE/GHSA/PYSEC. Free, no auth, structured JSON, version-aware. *Primary, reliable source.*
- **GitHub Security Advisories** (`github.com/advisories?query=type:malware+ecosystem:...`) — **scrapes HTML** (no API), one fetch per ecosystem (npm/pip), cached per run. Heuristic name extraction from backtick/quote patterns + word-boundary matching. Free, no auth, but **brittle** (breaks if GitHub markup changes), uses spoofed browser User-Agent.
- Coverage: **npm and PyPI/pip only**. No API keys needed for either.

## CLI
```
maloss [files...] [-r/--remote URL] [-j/--json] [-o/--output FILE] [--no-color]
```
- Exit codes: `0` clean, `1` malicious found.
- Output: console (banner + colored emoji findings) or file; JSON mode for automation.

## Output Shape (JSON mode)
```json
{
  "analyzed_by": "MALOSS at <ISO timestamp>",
  "total_packages_scanned": N,
  "malicious_packages_found": N,
  "remote_source": null,
  "findings": [
    {
      "package_name": "...",
      "id": "MAL-YYYY-NNNN",
      "severity": "Malware",
      "source": "OSV",
      "summary": "...",
      "affected_versions": ["..."],
      "url": "https://osv.dev/vulnerability/MAL-YYYY-NNNN"
    }
  ]
}
```

## Known Risks / Watch-Items
- **Dual-implementation drift** between `.py` and `.js`.
- **GitHub source is fragile** (HTML scraping, spoofed User-Agent).
- **Sequential per-package API calls** — large lockfiles → many OSV requests, possible throttling.
- `test-everything.sh` hardcoded path (`/Users/paulmccarty_1/projects/maloss`) makes it non-portable.
- In `maloss.js`, top-of-file `red`/`green`/`reset` constants (lines 19–21) are double-escaped and unused (the `Colors` class is what's actually used).
