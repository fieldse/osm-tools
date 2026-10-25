package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/fieldse/osm-tools/internal/cache"
	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/ecosystem"
	"github.com/fieldse/osm-tools/internal/infer"
	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/fieldse/osm-tools/internal/output"
	"github.com/fieldse/osm-tools/internal/verdict"
	"github.com/spf13/cobra"
)

// newCheckCmd builds `osm check` — a single ad-hoc lookup. No caching.
func newCheckCmd(deps *appDeps) *cobra.Command {
	var (
		ecosystem string
		version   string
		typeFlag  string
		debug     bool
	)

	cmd := &cobra.Command{
		Use:   "check <identifier>",
		Short: "Look up a package, domain, IP, or container image",
		Long: "Look up a package, domain, IP, or container image against OSM.\n\n" +
			"Package names must match the registry exactly, including the npm scope:\n" +
			"  @scope/name is matched; dropping @ or the scope is not.\n" +
			"An unrecognized name returns not-malicious, so CLEAN means \"not in OSM's\n" +
			"database,\" not \"verified safe\" — a typo'd or unscoped name will look clean.\n\n" +
			"Repositories, URLs and wallet addresses are not supported.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cmd, deps, args[0], typeFlag, ecosystem, version, debug)
		},
	}

	cmd.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "package ecosystem (npm, pypi, maven, …); implies a package lookup")
	cmd.Flags().StringVar(&version, "version", "", "package version (optional)")
	cmd.Flags().StringVarP(&typeFlag, "type", "T", "", "explicit type: package|domain|ip|docker (overrides inference and -e)")
	cmd.Flags().BoolVar(&debug, "debug", false, "print the API request and response status to stderr")

	return cmd
}

func runCheck(cmd *cobra.Command, deps *appDeps, identifier, typeFlag, ecosystemFlag, version string, debug bool) error {
	eco, err := checkEcosystem(ecosystemFlag)
	if err != nil {
		return err
	}
	kind, err := resolveCheckType(identifier, typeFlag, eco)
	if err != nil {
		return err
	}
	if kind == infer.TypeDomain {
		identifier = infer.NormalizeDomain(identifier)
	}

	c, err := deps.apiClient()
	if err != nil {
		return err
	}
	if debug {
		c.SetDebug(cmd.ErrOrStderr())
	}

	res, status, note, err := checkWithMavenFallback(cmd.Context(), c, client.Query{
		Type:       kind,
		Identifier: identifier,
		Ecosystem:  eco,
		Version:    version,
	})
	if err != nil {
		return err
	}

	output.CheckDetail(cmd.OutOrStdout(), identifier, kind, res, status, note)
	// A malicious verdict is information, not a failure: check always exits 0.
	return nil
}

// checkEcosystem lowercases the -e value and validates it. Empty means unset.
func checkEcosystem(flag string) (string, error) {
	eco := strings.ToLower(strings.TrimSpace(flag))
	if eco != "" && !ecosystem.IsValid(eco) {
		return "", osmerr.Usagef("unknown ecosystem %q; valid: %s", flag, strings.Join(ecosystem.All(), ", "))
	}
	return eco, nil
}

// resolveCheckType picks the lookup type: --type wins, then -e forces a
// package, then inference. Unsupported asset types and a package lookup with
// no ecosystem are usage errors. URLs and wallets are rejected even under an
// explicit --type; a repository-shaped name is not, so --type docker still
// reaches an untagged image on a private registry.
func resolveCheckType(identifier, typeFlag, ecosystem string) (string, error) {
	var kind string
	switch {
	case typeFlag != "":
		if infer.IsUnsupportedAsset(typeFlag) {
			return "", unsupportedAsset(typeFlag)
		}
		if !infer.IsSupported(typeFlag) {
			return "", osmerr.Usagef("unknown --type %q; must be one of package|domain|ip|docker", typeFlag)
		}
		kind = typeFlag
	case ecosystem != "":
		kind = infer.TypePackage
	default:
		kind = infer.Type(identifier)
	}

	if kind != infer.TypePackage {
		asset := infer.Type(identifier)
		if infer.IsUnsupportedAsset(asset) && (typeFlag == "" || asset != infer.TypeRepository) {
			return "", unsupportedAsset(asset)
		}
	}
	if kind == infer.TypePackage && ecosystem == "" {
		return "", osmerr.Usagef("package lookups require --ecosystem (e.g. -e npm); or set --type for a domain/ip/docker lookup")
	}
	return kind, nil
}

func unsupportedAsset(kind string) error {
	return osmerr.Usagef("%s lookups are not supported; osm check handles packages, domains, IPs and container images "+
		"(pass -e <ecosystem> for a package with this name, or --type docker for an image)", kind)
}

// checkWithMavenFallback runs q and returns the result, its verdict and an
// optional note. A CLEAN Maven groupId:artifactId lookup is retried once with
// the bare artifactId, since OSM stores Maven records under either form; a hit
// found only that way is at most REVIEW.
func checkWithMavenFallback(ctx context.Context, l cache.Lookup, q client.Query) (client.CheckResult, verdict.Status, string, error) {
	res, err := l.Check(ctx, q)
	if err != nil {
		return client.CheckResult{}, "", "", err
	}
	status := verdict.Of(res, q.Version, false)

	artifact, ok := mavenArtifactID(q)
	if status != verdict.Clean || !ok {
		return res, status, "", nil
	}

	fq := q
	fq.Identifier = artifact
	fres, err := l.Check(ctx, fq)
	if err != nil {
		return client.CheckResult{}, "", "", err
	}
	fstatus := verdict.Of(fres, q.Version, true)
	if fstatus == verdict.Clean {
		return res, status, "", nil
	}
	note := fmt.Sprintf("no record for %q; matched artifactId %q only, which may belong to a different groupId", q.Identifier, artifact)
	return fres, fstatus, note, nil
}

// mavenArtifactID returns the text after the last ":" of a Maven package
// identifier, if there is a non-empty one.
func mavenArtifactID(q client.Query) (string, bool) {
	if q.Type != infer.TypePackage || q.Ecosystem != ecosystem.Maven {
		return "", false
	}
	i := strings.LastIndex(q.Identifier, ":")
	if i < 0 || i == len(q.Identifier)-1 {
		return "", false
	}
	return q.Identifier[i+1:], true
}
