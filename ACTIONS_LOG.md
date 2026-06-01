# Actions Log

- 2026-06-02 change - **phase 1 foundation**: set up the CLI skeleton, shared error types, and the rule that maps failures to exit codes
- 2026-06-02 change - **phase 2 config & auth**: added the `osm config` command to save an API key and the logic that picks a token from flag, env var, or saved file
- 2026-06-02 change - **phase 3 api client**: built the layer that talks to the OSM service, keeps requests under the rate limit, and sorts out the different ways a request can fail
- 2026-06-02 change - **phase 4 check command**: added `osm check`, which guesses whether you're asking about a package, domain, IP, or image, looks it up, and prints the result
- 2026-06-02 change - **phase 5 cache**: added a local 24-hour memory of past lookups so repeated scans skip re-asking the API; not yet used by any command
- 2026-06-02 change - **phase 6 sweep**: added `osm sweep`, which reads a dependency file, checks every package at once, prints the results, and can fail a CI build if anything's malicious
- 2026-06-02 change - **phase 7 latest**: added `osm latest`, which pulls the most recently flagged threats for chosen ecosystems (or all) and prints them as JSON
- 2026-06-02 change - **structure cleanup**: moved type-guessing and the list of known ecosystems out of the command layer into their own focused pieces, and removed a duplicated helper, after a structural review
- 2026-06-02 change - **phase 8 hardening**: added end-to-end tests that run the real program, a timing test proving request pacing works, refreshed the docs, and confirmed a clean build before release
- 2026-06-02 change - **check command debug**: added a `--debug` flag to `check` that prints the API request and response status (never the token)
- 2026-06-02 change - **dropped .env**: removed the unused .env convention the program never read; documented the export and `osm config` paths instead
- 2026-06-02 change - **build script**: added build.sh that compiles the tool into ./bin
- 2026-06-02 bug - **wrong API base path and response shapes**: live calls 404'd because the base URL and the check/latest response field layouts were modeled from notes, not the real API; corrected against the live docs and verified working
