# TODO

- Render non-malicious check/sweep results as "NOT FOUND" instead of "CLEAN" — the API only knows malicious vs. not-in-database, so CLEAN overstates safety (use the `message`/not-found signal).
- Add `-n` flag to `latest` to limit the number of results returned.
