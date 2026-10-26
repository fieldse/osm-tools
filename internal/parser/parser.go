// Package parser extracts direct dependencies from manifest files. It owns the
// Package domain type and must not import the API client — sweep maps a Package
// to a client query at the call site.
package parser

import (
	"path/filepath"
	"strings"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// Package is one direct dependency from a manifest.
type Package struct {
	Name      string
	Version   string // may be empty if the manifest pins no version
	Ecosystem string // an ecosystem.* identifier
}

// parsers maps each supported manifest base name to its parser, in the order
// the usage message lists them.
var parsers = []struct {
	name  string
	parse func(path string) ([]Package, error)
}{
	{"package.json", parsePackageJSON},
	{"package-lock.json", parsePackageLock},
	{"pnpm-lock.yaml", parsePnpmLock},
	{"yarn.lock", parseYarnLock},
	{"requirements.txt", parseRequirements},
	{"poetry.lock", parsePoetryLock},
}

// Parse reads the manifest at path and returns its direct dependencies. The
// format is chosen by the file's base name; an unrecognized name is a usage
// error.
func Parse(path string) ([]Package, error) {
	base := filepath.Base(path)
	names := make([]string, 0, len(parsers))
	for _, p := range parsers {
		if p.name == base {
			return p.parse(path)
		}
		names = append(names, p.name)
	}
	return nil, osmerr.Usagef("unrecognized manifest %q; supported: %s", base, strings.Join(names, ", "))
}
