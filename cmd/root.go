package cmd

import (
	"context"

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

	return root
}

// buildDeps populates appDeps from parsed flags and the environment. Token
// resolution is wired in phase 2; for now it records the base URL and the raw
// flag value.
func buildDeps(deps *appDeps, tokenFlag string) error {
	deps.baseURL = resolveBaseURL()
	deps.token = tokenFlag
	return nil
}
