package parser

import (
	"fmt"
	"sort"

	"github.com/BurntSushi/toml"

	"github.com/fieldse/osm-tools/internal/ecosystem"
)

// poetryLock mirrors the subset of poetry.lock we need: the array of
// [[package]] tables, each carrying an exact pinned name and version.
type poetryLock struct {
	Packages []poetryPackage `toml:"package"`
}

// poetryPackage is one [[package]] entry in a poetry.lock file.
type poetryPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

// parsePoetryLock reads a poetry.lock (TOML) and returns every [[package]]
// entry as a Package, with versions used verbatim. The result is sorted by Name.
func parsePoetryLock(path string) ([]Package, error) {
	var lock poetryLock
	if _, err := toml.DecodeFile(path, &lock); err != nil {
		return nil, fmt.Errorf("parse poetry.lock %q: %w", path, err)
	}

	pkgs := make([]Package, 0, len(lock.Packages))
	for _, p := range lock.Packages {
		pkgs = append(pkgs, Package{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: ecosystem.PyPI,
		})
	}

	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	return pkgs, nil
}
