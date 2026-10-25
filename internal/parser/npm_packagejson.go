package parser

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/fieldse/osm-tools/internal/ecosystem"
)

// packageJSON is the minimal shape we read from a package.json manifest. Only
// direct dependency maps are decoded; everything else is ignored.
type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// readPackageJSON reads and decodes the package.json at path.
func readPackageJSON(path string) (packageJSON, error) {
	data, err := readManifest(path)
	if err != nil {
		return packageJSON{}, fmt.Errorf("read package.json %q: %w", path, err)
	}
	var manifest packageJSON
	if err := json.Unmarshal(data, &manifest); err != nil {
		return packageJSON{}, fmt.Errorf("parse package.json %q: %w", path, err)
	}
	return manifest, nil
}

// directSpecs merges dependencies, devDependencies and optionalDependencies
// into one name→spec map.
func (m packageJSON) directSpecs() map[string]string {
	specs := make(map[string]string, len(m.Dependencies)+len(m.DevDependencies)+len(m.OptionalDependencies))
	for _, deps := range []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies} {
		for name, spec := range deps {
			specs[name] = spec
		}
	}
	return specs
}

// parsePackageJSON reads the package.json at path and returns its direct
// dependencies, merging the dependencies, devDependencies and
// optionalDependencies objects. Only an
// exact version is kept; a range leaves Version empty, and non-registry specs
// are skipped (see npmSpec). The result is sorted by Name.
func parsePackageJSON(path string) ([]Package, error) {
	manifest, err := readPackageJSON(path)
	if err != nil {
		return nil, err
	}

	specs := manifest.directSpecs()
	pkgs := make([]Package, 0, len(specs))
	for key, spec := range specs {
		name, version, ok := npmSpec(key, spec)
		if !ok {
			continue
		}
		pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: ecosystem.NPM})
	}

	sortPackages(pkgs)
	return pkgs, nil
}

// sortPackages orders by Name, then Version, for deterministic output.
func sortPackages(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
}
