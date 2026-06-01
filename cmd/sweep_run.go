package cmd

import (
	"context"

	"github.com/fieldse/osm-tools/internal/cache"
	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/infer"
	"github.com/fieldse/osm-tools/internal/parser"
	"golang.org/x/sync/errgroup"
)

// sweepResult pairs an input package with its check outcome, preserving the
// input's position for deterministic output.
type sweepResult struct {
	Package parser.Package
	Result  client.CheckResult
}

// maxInFlight bounds concurrent goroutines. The rate limiter is the real
// throttle; this just caps memory/socket use.
const maxInFlight = 8

// sweepPackages checks each package concurrently through l, returning results in
// input order. A malicious verdict is NOT an error and does not cancel the
// group; a hard error (network/5xx/auth) cancels remaining work and is returned.
func sweepPackages(ctx context.Context, l cache.Lookup, pkgs []parser.Package) ([]sweepResult, error) {
	results := make([]sweepResult, len(pkgs))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxInFlight)

	for i, p := range pkgs {
		i, p := i, p
		g.Go(func() error {
			res, err := l.Check(ctx, client.Query{
				Type:       infer.TypePackage, // manifest entries are always packages
				Identifier: p.Name,
				Ecosystem:  p.Ecosystem,
				Version:    p.Version,
			})
			if err != nil {
				return err
			}
			results[i] = sweepResult{Package: p, Result: res}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return results, err
	}
	return results, nil
}
