// Package parser extracts direct dependencies from manifest files. It owns the
// Package domain type and must not import the API client — sweep maps a Package
// to a client query at the call site.
package parser

import (
	"path/filepath"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// Package is one direct dependency from a manifest.
type Package struct {
	Name      string
	Version   string // may be empty if the manifest pins no version
	Ecosystem string // an ecosystem.* identifier
}

// Parse reads the manifest at path and returns its direct dependencies. The
// format is chosen by the file's base name; an unrecognized name is a usage
// error.
func Parse(path string) ([]Package, error) {
	switch filepath.Base(path) {
	case "package.json":
		return parsePackageJSON(path)
	case "package-lock.json":
		return parsePackageLock(path)
	case "requirements.txt":
		return parseRequirements(path)
	case "poetry.lock":
		return parsePoetryLock(path)
	default:
		return nil, osmerr.Usagef("unrecognized manifest %q; supported: package.json, package-lock.json, requirements.txt, poetry.lock", filepath.Base(path))
	}
}
