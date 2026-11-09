---
status: ACCEPTED (approved by the maintainer, 2026-11-08)
date: 2026-11-08
deciders: user
---

# 0003: PII scan allowlist for this repo

## Decision

Add **`.gitleaks-pi.toml`** at the repo root. The global PII hook (`pi-check.sh`) reads it on every commit and push. It extends the global PI rules with `path = "@pi-global"` and adds two allowlists, both limited to the rule `pi-tilde-private-dir`:

| Allowlist | Match | Why |
|---|---|---|
| Config and cache directory | regex `~/\.osm\b`, in any file | `~/.osm` is where the tool keeps `config.json` and its cache. The README, docs, code comments and tests name it on purpose. It is the tool's path, not the maintainer's. |
| Sample reports | path `^examples/` | The sample threat reports quote malware IOCs, including tilde paths to credential files that the malware reads. They are indicators, not paths on this machine. |

Every other PII rule stays fully active, in every file, including `examples/`.

## Why an allowlist and not an opt-out

- `git config pi.scan false` would turn off every PII rule and the identity check for the whole repo.
- The allowlist silences one rule for two known cases. A home path, real name, work handle or internal name anywhere in the repo still blocks the commit.

## Evidence (collected 2026-11-08)

| Check | Result |
|---|---|
| Staged changes, before | `pi-check.sh staged` failed on 4 `~/.osm/config.json` lines (README.md, cmd/config.go, docs/submit.md). |
| Staged changes, after | `pi-check.sh staged` passes. |
| History, before | 40 PII findings across all commits. |
| History, after | 2 findings remain, both outside this allowlist's scope (see below). |
| Rule scoping | Tested in a throwaway repo with gitleaks 8.30.1: a real-name line in `examples/` and a different tilde path on the same line as `~/.osm/` both still fail. |

## Not covered

- `docs/maloss-reference.md` line 57 (commit 561de1d) quotes a third-party macOS home path from the MalOSS project. Rule `pi-macos-home-path`. Left blocked.
- `cmd/submit.go` (commit 561de1d) has IOC text with a credential-file tilde path in sample report data, outside `examples/`. Rule `pi-tilde-private-dir`. Left blocked.

## Conditions

1. **One rule only.** Both allowlists keep `targetRules = ["pi-tilde-private-dir"]`. Widening either one needs a new decision record.
2. **Extend the global rules.** The file keeps `path = "@pi-global"` under `[extend]`. Without it the hook refuses to run.
3. **No new rules.** Rules added to this file never run, because the hook enables only rule IDs from the global PI config.
4. **No other secrets.** This file affects the PII scan only. The policy gitleaks scan (`.gitleaks.toml`, absent here) is unchanged.
