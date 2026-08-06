Summary: Add `osm submit` — file a malicious-package report to OpenSourceMalware.com

* **Report to the community:** adds the first command that sends data out to OSM, letting anyone file a threat report from the command line instead of only looking things up
* **Safety before sending:** you always see exactly what will be sent and have to approve it first — and a non-interactive run refuses rather than sending anything blind
* **Defuses live threats automatically:** malware links and addresses in the write-up are neutralized before sending so nobody clicks them by accident, while the sources you cited are left intact

Changes:
* (feat) **submit command:** adds `osm submit` with three ways to compose a report — a template file, a JSON file, or guided prompts — all sharing one validate → defang → preview → confirm → send pipeline
* (feat) **report core:** new self-contained package that parses each input format, checks the required fields, and does the link-defusing, all independently testable
* (client) **submit endpoint:** adds the call to OSM's `POST /submit-threat-report`, mapping our field names to the service's and turning each documented rejection into a clear message
* (security) **IOC defanging:** neutralizes live URLs and IPs in the report body; hardened after an adversarial pass to also catch links touching punctuation and credentialed URLs, and to stop mangling clock times
* (test) **test-first coverage:** the whole feature was built tests-first, with extra regression tests locking in the security fixes; full suite green under the race detector
* (docs) **API path correction:** fixes the internal API guide — the real submit path is `/submit-threat-report`, verified against the official docs
* (fix) **no network before confirm:** a non-interactive run without approval now refuses before making any request, honoring the "nothing sent until you approve" promise
