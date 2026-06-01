package cmd

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/ecosystem"
	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// newLatestCmd builds `osm latest` — recent verified threats per ecosystem.
func newLatestCmd(deps *appDeps) *cobra.Command {
	var ecosystemFlag string

	cmd := &cobra.Command{
		Use:   "latest",
		Short: "Fetch the most recent verified threats per ecosystem",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLatest(cmd, deps, ecosystemFlag)
		},
	}

	cmd.Flags().StringVarP(&ecosystemFlag, "ecosystem", "e", "", "comma-separated ecosystems (default: all); e.g. -e npm,pypi")

	return cmd
}

func runLatest(cmd *cobra.Command, deps *appDeps, ecosystemFlag string) error {
	ecosystems, err := selectEcosystems(ecosystemFlag)
	if err != nil {
		return err
	}

	c, err := deps.apiClient()
	if err != nil {
		return err
	}

	grouped, err := fetchLatest(cmd.Context(), c, ecosystems)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(grouped)
}

// selectEcosystems parses the comma-separated flag (no spaces) into a validated
// list, defaulting to all recognized ecosystems when empty.
func selectEcosystems(flag string) ([]string, error) {
	if strings.TrimSpace(flag) == "" {
		return ecosystem.All(), nil
	}

	var out []string
	for _, e := range strings.Split(flag, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !ecosystem.IsValid(e) {
			return nil, osmerr.Usagef("unknown ecosystem %q; valid: %s", e, strings.Join(ecosystem.All(), ", "))
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, osmerr.Usagef("no ecosystems given; valid: %s", strings.Join(ecosystem.All(), ", "))
	}
	return out, nil
}

// fetchLatest queries each ecosystem concurrently and returns results grouped by
// ecosystem. The API is inherently per-ecosystem, so grouping mirrors it. A hard
// error from any ecosystem cancels the rest and is returned.
func fetchLatest(ctx context.Context, c *client.Client, ecosystems []string) (map[string][]client.LatestThreat, error) {
	results := make([][]client.LatestThreat, len(ecosystems))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxInFlight)

	for i, eco := range ecosystems {
		i, eco := i, eco
		g.Go(func() error {
			threats, err := c.QueryLatest(ctx, eco)
			if err != nil {
				return err
			}
			results[i] = threats
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	grouped := make(map[string][]client.LatestThreat, len(ecosystems))
	for i, eco := range ecosystems {
		grouped[eco] = results[i]
	}
	return grouped, nil
}
