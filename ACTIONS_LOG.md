# Actions Log

- 2026-06-02 change - **phase 1 foundation**: set up the CLI skeleton, shared error types, and the rule that maps failures to exit codes
- 2026-06-02 change - **phase 2 config & auth**: added the `osm config` command to save an API key and the logic that picks a token from flag, env var, or saved file
- 2026-06-02 change - **phase 3 api client**: built the layer that talks to the OSM service, keeps requests under the rate limit, and sorts out the different ways a request can fail
- 2026-06-02 change - **phase 4 check command**: added `osm check`, which guesses whether you're asking about a package, domain, IP, or image, looks it up, and prints the result
- 2026-06-02 change - **phase 5 cache**: added a local 24-hour memory of past lookups so repeated scans skip re-asking the API; not yet used by any command
- 2026-06-02 change - **phase 6 sweep**: added `osm sweep`, which reads a dependency file, checks every package at once, prints the results, and can fail a CI build if anything's malicious
- 2026-06-02 change - **phase 7 latest**: added `osm latest`, which pulls the most recently flagged threats for chosen ecosystems (or all) and prints them as JSON
- 2026-06-02 change - **structure cleanup**: moved type-guessing and the list of known ecosystems out of the command layer into their own focused pieces, and removed a duplicated helper, after a structural review
