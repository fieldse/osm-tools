# evil-utils postinstall credential stealer

- Type: package
- Resource: evil-utils
- Package name: evil-utils
- Registry: npm
- Publisher: totally-legit-dev
- Contact: you@example.com
- Affected versions: 3.3.1, 3.3.2
- Severity: high
- First seen: 2026-07-14
- Last seen: 2026-07-16
- OSV: https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx
- Tags: postinstall, exfil, credential-theft

## Description
The 3.3.1 release adds a postinstall script absent from the published GitHub
tag. On install it reads ~/.npmrc and ~/.aws/credentials and POSTs their
contents to a hardcoded host, then deletes its own log file to hide the run.
The 3.3.0 release is clean; the malicious code appears only from 3.3.1 onward.

## Payload / IOCs
postinstall -> node scripts/setup.js
exfil endpoint: http://evil.example.com/collect
reads: ~/.npmrc, ~/.aws/credentials
c2 fallback ip: 203.0.113.42

## Evidence
- https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx
- https://www.npmjs.com/package/evil-utils/v/3.3.1
- https://github.com/totally-legit-dev/evil-utils/commit/deadbeef
