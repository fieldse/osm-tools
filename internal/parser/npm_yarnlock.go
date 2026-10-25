package parser

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fieldse/osm-tools/internal/ecosystem"
)

// yarnBerryMarker identifies a yarn 2+ (berry) lockfile, which is YAML.
var yarnBerryMarker = regexp.MustCompile(`(?m)^__metadata:`)

// yarnBerryEntry is the part of a berry lockfile entry we read.
type yarnBerryEntry struct {
	Version string `yaml:"version"`
}

// parseYarnLock reads a yarn.lock (v1 or berry) and returns the direct deps
// named by the package.json beside it, each resolved to the version locked for
// its exact name@spec descriptor. yarn.lock alone cannot tell direct deps from
// transitive ones, so a missing package.json is an error.
func parseYarnLock(path string) ([]Package, error) {
	data, err := readManifest(path)
	if err != nil {
		return nil, fmt.Errorf("read yarn.lock %q: %w", path, err)
	}
	manifest, err := readPackageJSON(filepath.Join(filepath.Dir(path), "package.json"))
	if err != nil {
		return nil, fmt.Errorf("yarn.lock needs the package.json beside it to find direct deps: %w", err)
	}

	berry := yarnBerryMarker.Match(data)
	var locked map[string]string
	if berry {
		locked, err = yarnBerryVersions(data)
		if err != nil {
			return nil, fmt.Errorf("parse yarn.lock %q: %w", path, err)
		}
	} else {
		locked = yarnV1Versions(data)
	}

	var pkgs []Package
	for key, spec := range manifest.directSpecs() {
		name, version, ok := npmSpec(key, spec)
		if !ok {
			continue
		}
		if v := npmExactVersion(locked[yarnDescriptor(key, spec, berry)]); v != "" {
			version = v
		}
		pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: ecosystem.NPM})
	}

	sortPackages(pkgs)
	return pkgs, nil
}

// yarnDescriptor is the lockfile key yarn writes for a package.json entry:
// name@spec in v1, and name@npm:spec in berry unless the spec has a protocol.
func yarnDescriptor(name, spec string, berry bool) string {
	if berry && !strings.Contains(spec, ":") {
		spec = "npm:" + spec
	}
	return name + "@" + spec
}

// yarnBerryVersions maps every descriptor in a berry lockfile to its version.
func yarnBerryVersions(data []byte) (map[string]string, error) {
	var entries map[string]yarnBerryEntry
	if err := decodeYAML(data, &entries); err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for key, e := range entries {
		for _, d := range splitYarnKey(key) {
			out[d] = e.Version
		}
	}
	return out, nil
}

// yarnV1Versions maps every descriptor in a v1 lockfile to its version. An
// entry starts at an unindented `key[, key...]:` line; its version is the
// `  version "x"` line indented by exactly two spaces.
func yarnV1Versions(data []byte) map[string]string {
	out := make(map[string]string)
	var keys []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			keys = nil
			if head, ok := strings.CutSuffix(line, ":"); ok {
				keys = splitYarnKey(head)
			}
			continue
		}
		if v, ok := strings.CutPrefix(line, "  version "); ok {
			for _, k := range keys {
				out[k] = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	return out
}

// splitYarnKey splits a lockfile entry key into its unquoted descriptors.
func splitYarnKey(key string) []string {
	parts := strings.Split(key, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.Trim(strings.TrimSpace(p), `"`); p != "" {
			out = append(out, p)
		}
	}
	return out
}
