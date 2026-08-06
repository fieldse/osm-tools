# `osm submit` — filing a threat report

`osm submit` files a threat report to OpenSourceMalware.com. It's the only
write command in the tool, so the pipeline is deliberately cautious: every run
is **collect → validate → defang → preview → confirm → submit**, and nothing is
sent until you type `y` at the confirm prompt.

There are three ways to compose a report — a **template file**, a **JSON file**,
or the **interactive wizard** — and three no-network escape hatches for
practising without touching the API.

> The examples below use a made-up `evil-utils` package. Ready-to-copy files
> live in [`examples/`](../examples): [`threat-report.md`](../examples/threat-report.md)
> and [`threat-report.json`](../examples/threat-report.json).

---

## Try it without sending anything

Every command here is safe with `--emit-json` (print the assembled report and
exit) or `--dry-run` (run the full local pipeline and stop before submit). Both
make **zero network calls** and need no API token:

```sh
osm submit examples/threat-report.md --emit-json
```

```sh
osm submit examples/threat-report.md --dry-run
```

Print a blank template to start from:

```sh
osm submit --template > my-report.md
```

---

## 1. Template file (default)

A plaintext/markdown file. Field lines are `- Key: value`; the three long
sections are `## Description`, `## Payload / IOCs`, and `## Evidence`. Only
`Type`, `Resource`, and `Description` are required — everything else is optional.

```markdown
# evil-utils postinstall credential stealer

- Type: package
- Resource: evil-utils
- Registry: npm
- Severity: high
- First seen: 2026-07-14

## Description
The 3.3.1 release adds a postinstall script, absent from the GitHub tag, that
reads ~/.npmrc and POSTs it to a hardcoded host.

## Payload / IOCs
exfil endpoint: http://evil.example.com/collect

## Evidence
- https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx
```

Submit it (prompts for confirmation first):

```sh
osm submit examples/threat-report.md
```

## 2. JSON file (`--from-json`)

Keyed by the API field names — scriptable and CI-friendly. A misspelled key is
rejected with the list of accepted keys, so typos fail loudly instead of
silently dropping data.

```json
{
  "report_type": "package",
  "resource_identifier": "evil-utils",
  "threat_description": "3.3.1 adds a postinstall script that exfiltrates ~/.npmrc.",
  "registry": "npm",
  "severity_level": "high",
  "payload_description": "exfil endpoint: http://evil.example.com/collect",
  "evidence_references": ["https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx"]
}
```

Submit from a file:

```sh
osm submit --from-json examples/threat-report.json
```

Or pipe it in on stdin with `-`:

```sh
cat examples/threat-report.json | osm submit --from-json -
```

## 3. Interactive wizard (`-i`)

Guided prompts, no file needed. Each prompt shows whether the field is
`(required)` or `(optional)`, its accepted values or an example, and any default
right on the input line — press Enter to accept it. `report_type` defaults to
`package`, `registry` to `npm`, and `first_seen` to today. Ctrl-C aborts
cleanly at any point.

```sh
osm submit -i
```

```
report_type (required)
  package|container|repository|url|domain|ip|wallet
> package
resource_identifier (required)
  what you're reporting, e.g. @acme/utils
> evil-utils
first_seen (optional)
  YYYY-MM-DD
> 2026-07-16
```

The wizard requires a real terminal. In CI, pipe a JSON report with
`--from-json -` instead.

---

## Confirmation and CI

Interactive runs preview the report and wait for `y`. Non-interactive runs
(piped stdin, no TTY) **refuse to submit** unless you pass `-y`/`--yes`, so a
report is never sent blind:

```sh
osm submit examples/threat-report.json --yes
```

## Defanging

Live indicators in `payload_description` are neutralized before sending
(`http://evil.example.com` → `hxxp://evil[.]example[.]com`, `203.0.113.42` →
`203[.]0[.]113[.]42`). Evidence and OSV URLs are **never** defanged — they're
citations meant to be followed. Send indicators verbatim with `--no-defang`:

```sh
osm submit examples/threat-report.md --no-defang
```

---

## Flags

| Flag | Effect |
|---|---|
| `-i`, `--interactive` | compose through guided prompts |
| `--from-json FILE` | read a structured JSON report (`-` = stdin) |
| `--template` | print the blank template and exit (no network) |
| `--emit-json` | print the assembled report as JSON and exit (no network) |
| `--dry-run` | run the local pipeline and stop before submit (no network) |
| `--no-defang` | send IOCs verbatim instead of neutralizing them |
| `-y`, `--yes` | assume yes to the confirm prompt; required in non-TTY/CI runs |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | submitted (or a no-network command completed) |
| `1` | operational failure — network, auth, `5xx`, or a rejected submit (403 report cap, 409 duplicate, 429 rate limit) |
| `2` | usage error — bad flag, conflicting input modes, missing required field, or a non-TTY run without `-y` |

## Notes and cautions

- **A real submit files a real report.** New/unverified accounts are capped at
  3 reports, and the free tier allows 10 submissions/hour. Use `--emit-json` or
  `--dry-run` to rehearse.
- **Pick exactly one input mode.** Combining `FILE`, `--from-json`, and `-i` is
  a usage error.
- **Set `contact_email` to a real address** if you want OSM to follow up — the
  examples ship with the placeholder `you@example.com`.
