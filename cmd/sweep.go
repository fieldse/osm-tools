package cmd

import (
	"fmt"

	"github.com/fieldse/osm-tools/internal/cache"
	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/fieldse/osm-tools/internal/output"
	"github.com/fieldse/osm-tools/internal/parser"
	"github.com/fieldse/osm-tools/internal/verdict"
	"github.com/spf13/cobra"
)

// newSweepCmd builds `osm sweep` — batch-checks a manifest's direct deps.
func newSweepCmd(deps *appDeps) *cobra.Command {
	var (
		file      string
		outputFmt string
		failOnAny bool
	)

	cmd := &cobra.Command{
		Use:   "sweep",
		Short: "Check a manifest's direct dependencies against OSM",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSweep(cmd, deps, file, outputFmt, failOnAny)
		},
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "manifest file (package.json, package-lock.json, pnpm-lock.yaml, yarn.lock, requirements.txt, poetry.lock)")
	cmd.Flags().StringVarP(&outputFmt, "output", "o", "table", "output format: table|json")
	cmd.Flags().BoolVar(&failOnAny, "fail-on-any", false, "exit 3 if any dependency is MALICIOUS or REVIEW (CI gate)")
	cmd.MarkFlagRequired("file")

	return cmd
}

func runSweep(cmd *cobra.Command, deps *appDeps, file, outputFmt string, failOnAny bool) error {
	if outputFmt != "table" && outputFmt != "json" {
		return osmerr.Usagef("unknown --output %q; must be table or json", outputFmt)
	}

	pkgs, err := parser.Parse(file)
	if err != nil {
		return err
	}
	pkgs = parser.Dedupe(pkgs)

	c, err := deps.apiClient()
	if err != nil {
		return err
	}

	// Cache wraps the client so repeat lookups skip the API. Load once; flush
	// once at the end (including on partial results from a cancelled run).
	store, err := deps.newCache()
	if err != nil {
		return err
	}
	_ = store.Load() // a bad/missing cache is non-fatal; start empty
	cached := cache.Wrap(c, store)

	results, sweepErr := sweepPackages(cmd.Context(), cached, pkgs)

	// Persist whatever was gathered, even on a hard error / cancellation.
	if flushErr := store.Flush(); flushErr != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: could not write cache:", flushErr)
	}

	if sweepErr != nil {
		return sweepErr // operational → exit 1
	}

	rows, hits := toRows(results)
	if err := render(cmd, outputFmt, rows); err != nil {
		return err
	}

	if failOnAny && len(hits) > 0 {
		return &osmerr.GateTriggered{Hits: hits}
	}
	if outputFmt == "table" {
		fmt.Fprintf(cmd.OutOrStdout(), "\nChecked %d package(s); %d malicious, %d review.\n",
			len(rows), countStatus(rows, verdict.Malicious), countStatus(rows, verdict.Review))
	}
	return nil
}

// toRows converts results to output rows (in input order) and collects the
// identifiers of MALICIOUS and REVIEW rows, which both trip --fail-on-any.
func toRows(results []sweepResult) (rows []output.SweepRow, hits []string) {
	rows = make([]output.SweepRow, 0, len(results))
	for _, r := range results {
		status := verdict.Of(r.Result, r.Package.Version, false)
		if status != verdict.Clean {
			hits = append(hits, packageLabel(r.Package))
		}
		rows = append(rows, output.SweepRow{
			Package:          r.Package.Name,
			Version:          r.Package.Version,
			Status:           string(status),
			Severity:         r.Result.Details.SeverityLevel,
			AffectedVersions: r.Result.AffectedVersions(),
			OSMURL:           r.Result.OSMURL,
		})
	}
	return rows, hits
}

// packageLabel is name@version, or just the name when no version was pinned.
func packageLabel(p parser.Package) string {
	if p.Version == "" {
		return p.Name
	}
	return p.Name + "@" + p.Version
}

func countStatus(rows []output.SweepRow, s verdict.Status) int {
	n := 0
	for _, r := range rows {
		if r.Status == string(s) {
			n++
		}
	}
	return n
}

func render(cmd *cobra.Command, format string, rows []output.SweepRow) error {
	if format == "json" {
		return output.SweepJSON(cmd.OutOrStdout(), rows)
	}
	output.SweepTable(cmd.OutOrStdout(), rows)
	return nil
}
