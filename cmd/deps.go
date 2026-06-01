package cmd

import (
	"net/http"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/osmerr"
	"golang.org/x/time/rate"
)

// appDeps carries the resolved dependencies shared across subcommands. It is
// built once in the root command's PersistentPreRunE (after flags are parsed)
// and passed to subcommand constructors — there is no package-level global
// state and no init()-time wiring.
//
// Phase 5 will add a cache-backed lookup for sweep; check uses the bare client.
type appDeps struct {
	// token is the resolved API token (--token → OSM_API_KEY → config file).
	token string

	// baseURL is the OSM API base URL. Overridable for tests/staging.
	baseURL string

	// limiter is the shared rate limiter. Constructed once so concurrent
	// requests (e.g. sweep goroutines) contend on a single 60-rpm bucket.
	limiter *rate.Limiter

	// httpClient is the rate-limited HTTP client built from limiter. Injectable
	// so tests can point the client at an httptest server.
	httpClient *http.Client
}

// requireToken returns the resolved token or an actionable ErrNoToken. Commands
// that call the API use this so the failure carries the remedy.
func (d *appDeps) requireToken() (string, error) {
	if d.token == "" {
		return "", osmerr.ErrNoToken
	}
	return d.token, nil
}

// apiClient builds a Client from the resolved deps. It fails fast if no token
// is configured.
func (d *appDeps) apiClient() (*client.Client, error) {
	token, err := d.requireToken()
	if err != nil {
		return nil, err
	}
	return client.New(d.baseURL, token, d.httpClient), nil
}
