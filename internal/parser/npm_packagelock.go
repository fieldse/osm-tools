package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// lockfile mirrors the subset of package-lock.json we need. Both the v2/v3
// "packages" object and the v1 "dependencies" object are decoded; which one is
// populated tells us the format.
type lockfile struct {
	Packages     map[string]lockEntry `json:"packages"`
	Dependencies map[string]lockEntry `json:"dependencies"`
}

// lockEntry is one entry in either the "packages" or "dependencies" map. The
// root "" entry in v2/v3 uses Dependencies/DevDependencies to name direct deps;
// node_modules/<name> entries carry the resolved Version.
type lockEntry struct {
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// parsePackageLock reads an npm package-lock.json and returns only its DIRECT
// dependencies.
//
// For v2/v3 lockfiles it reads the direct dependency names from the root
// packages[""] entry's dependencies + devDependencies, then resolves each to a
// concrete version from packages["node_modules/<name>"].version, falling back to
// the spec string when no installed entry exists. For v1 lockfiles (no
// "packages" object) it best-effort takes the top-level "dependencies" map.
func parsePackageLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json %q: %w", path, err)
	}

	var lf lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse package-lock.json %q: %w", path, err)
	}

	var pkgs []Package
	if lf.Packages != nil {
		// v2/v3: the root "" entry names the direct deps.
		root := lf.Packages[""]
		direct := make(map[string]string)
		for name, spec := range root.Dependencies {
			direct[name] = spec
		}
		for name, spec := range root.DevDependencies {
			direct[name] = spec
		}
		for name, spec := range direct {
			version := spec
			if installed, ok := lf.Packages["node_modules/"+name]; ok && installed.Version != "" {
				version = installed.Version
			}
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   version,
				Ecosystem: EcosystemNPM,
			})
		}
	} else {
		// v1: no "packages" object; best-effort take top-level dependencies.
		for name, entry := range lf.Dependencies {
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   entry.Version,
				Ecosystem: EcosystemNPM,
			})
		}
	}

	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	return pkgs, nil
}
