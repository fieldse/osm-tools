package cmd

import "github.com/fieldse/osm-tools/internal/osmerr"

// appDeps carries the resolved dependencies shared across subcommands. It is
// built once in the root command's PersistentPreRunE (after flags are parsed)
// and passed to subcommand constructors — there is no package-level global
// state and no init()-time wiring.
//
// Later phases extend this struct: phase 3 adds the API client, phase 5 adds
// the cache-backed lookup. For now it holds what foundation resolves.
type appDeps struct {
	// token is the resolved API token (--token → OSM_API_KEY → config file).
	// Populated in phase 2; empty until then.
	token string

	// baseURL is the OSM API base URL. Overridable for tests/staging.
	baseURL string
}

// requireToken returns the resolved token or an actionable ErrNoToken. Commands
// that call the API use this so the failure carries the remedy.
func (d *appDeps) requireToken() (string, error) {
	if d.token == "" {
		return "", osmerr.ErrNoToken
	}
	return d.token, nil
}
