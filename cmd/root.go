package cmd

import (
	"context"
	"os"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/config"
	"github.com/spf13/cobra"
)

// defaultBaseURL is the OSM API base. Overridable via OSM_BASE_URL for tests
// and staging (kept as an env seam rather than a public flag to avoid
// expanding the CLI surface).
const defaultBaseURL = "https://api.opensourcemalware.com/v1"

// Execute builds the command tree and runs it with the given context. It
// returns the error from command execution so that main owns the exit-code
// mapping (cobra's default error handling is disabled via SilenceErrors).
func Execute(ctx context.Context) error {
	root := newRootCmd()
	return root.ExecuteContext(ctx)
}

func newRootCmd() *cobra.Command {
	deps := &appDeps{}

	var tokenFlag string

	root := &cobra.Command{
		Use:   "osm",
		Short: "Query the OpenSourceMalware.com API for malicious packages",
		Long: "osm checks packages, domains, IPs, and container images against the " +
			"OpenSourceMalware.com community-verified threat database.",
		// main maps returned errors to exit codes; don't let cobra print or
		// re-handle them.
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return buildDeps(deps, tokenFlag)
		},
	}

	root.PersistentFlags().StringVarP(&tokenFlag, "token", "t", "", "OSM API token (overrides OSM_API_KEY and config file)")

	// Subcommands are registered as their phases land.
	root.AddCommand(newConfigCmd())
	root.AddCommand(newCheckCmd(deps))
	root.AddCommand(newSweepCmd(deps))

	return root
}

// buildDeps populates appDeps from parsed flags, the environment, and the
// config file. It resolves the token but tolerates its absence: a missing token
// is not fatal here because some commands (config, help) don't need one.
// Commands that require auth check deps.token and fail with ErrNoToken.
func buildDeps(deps *appDeps, tokenFlag string) error {
	deps.baseURL = resolveBaseURL()

	store, err := config.New()
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}

	// ResolveToken returns ErrNoToken when all sources are empty; that's
	// acceptable at this stage, so swallow it and leave deps.token empty.
	token, err := config.ResolveToken(tokenFlag, os.Getenv("OSM_API_KEY"), cfg.Token)
	if err == nil {
		deps.token = token
	}

	// Shared rate limiter + HTTP client for all API-calling commands.
	deps.limiter = client.NewLimiter(client.DefaultRPM)
	deps.httpClient = client.NewRateLimitedClient(deps.limiter)
	return nil
}
