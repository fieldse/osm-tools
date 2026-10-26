Summary: Make osm match how the OSM API really works, and scan pnpm and yarn lockfiles

* **Fewer missed hits:** Lookups are now sent in the exact form OSM expects, so real malware no longer slips through as "clean" because of a wrong ecosystem name, a version range or a Maven naming quirk
* **A middle verdict:** Results are now malicious, needs review, or clean, and a CI gate fails on "needs review" too, rather than treating partial matches as safe
* **More projects covered:** Dependency scans now read pnpm and yarn lockfiles, and the token setup asks before overwriting a saved token

Changes:
* (fix) **package lookups:** the ecosystem flag always means a package lookup, is checked against the 12 supported ecosystems, and repos, URLs and wallets are rejected up front
* (feat) **review verdict:** one shared rule decides malicious, review or clean, and output now lists the affected versions and the OSM page link
* (fix) **maven fallback:** a miss on the full group and artifact name retries with the artifact alone, and any hit found that way is marked for review
* (feat) **pnpm and yarn lockfiles:** sweep reads pnpm v6 and v9 and yarn v1 and berry, with size limits on what it will parse
* (fix) **sweep accuracy:** version ranges are no longer sent as versions, optional dependencies are checked, npm aliases resolve, and old cache entries are discarded
* (fix) **rate limits:** per-minute limits are waited out and retried up to 3 times, while the daily limit stops the run with a clear error
* (feat) **safer token setup:** config asks before replacing a saved token, Ctrl-C leaves the terminal working, and show prints masked tokens
* (docs) **readme rewrite:** explains what osm does and doesn't catch, lists every ecosystem with its naming rules, and records both dependency decisions
