// Package ecosystem defines the package ecosystems OSM recognizes.
package ecosystem

// Recognized ecosystems.
const (
	NPM       = "npm"
	PyPI      = "pypi"
	Maven     = "maven"
	NuGet     = "nuget"
	RubyGems  = "rubygems"
	Packagist = "packagist"
	Crates    = "crates"
	Go        = "go"
)

// all is the canonical ordered list of recognized ecosystems.
var all = []string{NPM, PyPI, Maven, NuGet, RubyGems, Packagist, Crates, Go}

// All returns every recognized ecosystem.
func All() []string {
	return append([]string(nil), all...)
}

// IsValid reports whether e is a recognized ecosystem.
func IsValid(e string) bool {
	for _, s := range all {
		if s == e {
			return true
		}
	}
	return false
}
