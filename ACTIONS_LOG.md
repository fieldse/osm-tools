# Actions Log

- 2026-06-02 change - **phase 1 foundation**: set up the CLI skeleton, shared error types, and the rule that maps failures to exit codes
- 2026-06-02 change - **phase 2 config & auth**: added the `osm config` command to save an API key and the logic that picks a token from flag, env var, or saved file
- 2026-06-02 change - **phase 3 api client**: built the layer that talks to the OSM service, keeps requests under the rate limit, and sorts out the different ways a request can fail
