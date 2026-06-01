package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/fieldse/osm-tools/internal/ecosystem"
)

// packageJSON is the minimal shape we read from a package.json manifest. Only
// direct dependency maps are decoded; everything else is ignored.
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// parsePackageJSON reads the package.json at path and returns its direct
// dependencies, merging the dependencies and devDependencies objects. Version
// specs are returned verbatim (e.g. "^4.18.2"). The result is sorted by Name.
func parsePackageJSON(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package.json %q: %w", path, err)
	}

	var manifest packageJSON
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse package.json %q: %w", path, err)
	}

	pkgs := make([]Package, 0, len(manifest.Dependencies)+len(manifest.DevDependencies))
	for name, version := range manifest.Dependencies {
		pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: ecosystem.NPM})
	}
	for name, version := range manifest.DevDependencies {
		pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: ecosystem.NPM})
	}

	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	return pkgs, nil
}
