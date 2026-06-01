package cmd

import (
	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/fieldse/osm-tools/internal/output"
	"github.com/spf13/cobra"
)

// newCheckCmd builds `osm check` — a single ad-hoc lookup. No caching.
func newCheckCmd(deps *appDeps) *cobra.Command {
	var (
		ecosystem string
		version   string
		typeFlag  string
	)

	cmd := &cobra.Command{
		Use:   "check <identifier>",
		Short: "Look up a package, domain, IP, or container image",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cmd, deps, args[0], typeFlag, ecosystem, version)
		},
	}

	cmd.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "package ecosystem (npm, pypi, …); required for package lookups")
	cmd.Flags().StringVar(&version, "version", "", "package version (optional)")
	cmd.Flags().StringVarP(&typeFlag, "type", "T", "", "explicit type: package|domain|ip|docker (overrides inference)")

	return cmd
}

func runCheck(cmd *cobra.Command, deps *appDeps, identifier, typeFlag, ecosystem, version string) error {
	kind, err := resolveCheckType(identifier, typeFlag, ecosystem)
	if err != nil {
		return err
	}

	c, err := deps.apiClient()
	if err != nil {
		return err
	}

	res, err := c.Check(cmd.Context(), client.Query{
		Type:       kind,
		Identifier: identifier,
		Ecosystem:  ecosystem,
		Version:    version,
	})
	if err != nil {
		return err
	}

	output.CheckDetail(cmd.OutOrStdout(), identifier, kind, res)
	// A malicious verdict is information, not a failure: check always exits 0.
	return nil
}

// resolveCheckType applies the --type override or falls back to inference, then
// validates that a package lookup has an ecosystem.
func resolveCheckType(identifier, typeFlag, ecosystem string) (string, error) {
	kind := typeFlag
	if kind == "" {
		kind = inferType(identifier)
	} else if !isSupportedType(kind) {
		return "", osmerr.Usagef("unknown --type %q; must be one of package|domain|ip|docker", kind)
	}

	if kind == typePackage && ecosystem == "" {
		return "", osmerr.Usagef("package lookups require --ecosystem (e.g. -e npm); or set --type for a domain/ip/docker lookup")
	}
	return kind, nil
}
