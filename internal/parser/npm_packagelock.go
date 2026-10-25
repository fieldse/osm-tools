package parser

import (
	"encoding/json"
	"fmt"

	"github.com/fieldse/osm-tools/internal/ecosystem"
)

// lockfile mirrors the subset of package-lock.json we need. Both the v2/v3
// "packages" object and the v1 "dependencies" object are decoded; which one is
// populated tells us the format.
type lockfile struct {
	Packages     map[string]lockEntry `json:"packages"`
	Dependencies map[string]lockEntry `json:"dependencies"`
}

// lockEntry is one entry in either the "packages" or "dependencies" map. The
// root "" entry in v2/v3 uses its dependency maps to name direct deps;
// node_modules/<name> entries carry the resolved Version.
type lockEntry struct {
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// parsePackageLock reads an npm package-lock.json and returns only its direct
// dependencies. In v2/v3, it extracts direct deps from packages[""].dependencies,
// .devDependencies and .optionalDependencies, then resolves each to its concrete version from
// packages["node_modules/<name>"].version, falling back to the spec under the
// same rules as package.json. In v1, it takes the top-level "dependencies" map.
func parsePackageLock(path string) ([]Package, error) {
	data, err := readManifest(path)
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json %q: %w", path, err)
	}

	var lf lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse package-lock.json %q: %w", path, err)
	}

	var pkgs []Package
	if lf.Packages != nil {
		root := lf.Packages[""]
		direct := packageJSON{
			Dependencies:         root.Dependencies,
			DevDependencies:      root.DevDependencies,
			OptionalDependencies: root.OptionalDependencies,
		}
		for key, spec := range direct.directSpecs() {
			name, version, ok := npmSpec(key, spec)
			if !ok {
				continue
			}
			if installed := npmExactVersion(lf.Packages["node_modules/"+key].Version); installed != "" {
				version = installed
			}
			pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: ecosystem.NPM})
		}
	} else {
		// v1: an aliased or git dep carries its spec in the version field.
		for key, entry := range lf.Dependencies {
			name, version, ok := npmSpec(key, entry.Version)
			if !ok {
				continue
			}
			pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: ecosystem.NPM})
		}
	}

	sortPackages(pkgs)
	return pkgs, nil
}
