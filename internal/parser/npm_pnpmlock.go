package parser

import (
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/fieldse/osm-tools/internal/ecosystem"
)

// pnpmLock is the subset of pnpm-lock.yaml we read. v9 and v6 monorepos list
// projects under importers; a v6 single project puts its dependency maps at
// the top level, captured by the inline importer.
type pnpmLock struct {
	Importers    map[string]pnpmImporter `yaml:"importers"`
	pnpmImporter `yaml:",inline"`
}

// pnpmImporter holds one project's direct dependency maps.
type pnpmImporter struct {
	Dependencies         map[string]pnpmDep `yaml:"dependencies"`
	DevDependencies      map[string]pnpmDep `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmDep `yaml:"optionalDependencies"`
}

// pnpmDep is one direct dependency's resolved version reference.
type pnpmDep struct {
	Version string
}

// UnmarshalYAML accepts the {specifier, version} mapping of v6+ and the bare
// version scalar of v5.
func (d *pnpmDep) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		d.Version = n.Value
		return nil
	}
	var v struct {
		Version string `yaml:"version"`
	}
	if err := n.Decode(&v); err != nil {
		return err
	}
	d.Version = v.Version
	return nil
}

// parsePnpmLock reads a pnpm-lock.yaml and returns the union of every
// importer's direct dependencies, deduped. Local link:/file:/workspace: deps
// and git or tarball deps are skipped.
func parsePnpmLock(path string) ([]Package, error) {
	data, err := readManifest(path)
	if err != nil {
		return nil, fmt.Errorf("read pnpm-lock.yaml %q: %w", path, err)
	}
	var lock pnpmLock
	if err := decodeYAML(data, &lock); err != nil {
		return nil, fmt.Errorf("parse pnpm-lock.yaml %q: %w", path, err)
	}

	importers := []pnpmImporter{lock.pnpmImporter}
	for _, id := range sortedKeys(lock.Importers) {
		importers = append(importers, lock.Importers[id])
	}

	var pkgs []Package
	for _, imp := range importers {
		for _, deps := range []map[string]pnpmDep{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
			for _, key := range sortedKeys(deps) {
				name, version, ok := pnpmVersion(key, deps[key].Version)
				if !ok {
					continue
				}
				pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: ecosystem.NPM})
			}
		}
	}

	pkgs = Dedupe(pkgs)
	sortPackages(pkgs)
	return pkgs, nil
}

// pnpmVersion turns an importer's version reference into a name and exact
// version. It strips peer suffixes ("3.2.7(react@18.3.1)"), resolves aliases
// ("string-width@4.2.3", v6 "/string-width@4.2.3"), and reports ok=false for
// local and non-registry references.
func pnpmVersion(key, ref string) (name, version string, ok bool) {
	v, _, _ := strings.Cut(ref, "(")
	for _, local := range []string{"link:", "file:", "workspace:"} {
		if strings.HasPrefix(v, local) {
			return "", "", false
		}
	}
	if i := strings.IndexByte(v, '_'); i > 0 && npmExact.MatchString(v[:i]) {
		v = v[:i] // v5 peer suffix: 3.2.7_@types+node@22.20.0
	}
	v = strings.TrimPrefix(v, "/")
	name = key
	if i := strings.LastIndex(v, "@"); i > 0 {
		name, v = v[:i], v[i+1:]
	}
	if strings.ContainsAny(v, ":/") {
		return "", "", false
	}
	return name, npmExactVersion(v), true
}

// decodeYAML unmarshals untrusted YAML into typed dst, turning any decoder
// panic into an error.
func decodeYAML(data []byte, dst any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("YAML decoder failed: %v", r)
		}
	}()
	return yaml.Unmarshal(data, dst)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
