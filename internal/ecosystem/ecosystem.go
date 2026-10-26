// Package ecosystem defines the package ecosystems OSM recognizes.
package ecosystem

// Recognized ecosystems. Values are the API's case-sensitive ecosystem names.
const (
	NPM       = "npm"
	PyPI      = "pypi"
	Maven     = "maven"
	NuGet     = "nuget"
	RubyGems  = "rubygems"
	Packagist = "packagist"
	Crates    = "crates"
	Go        = "go"
	VSCode    = "vscode"
	OpenVSX   = "openvsx"
	Skills    = "skills"
	Brew      = "brew"
)

// all is the canonical ordered list of recognized ecosystems.
var all = []string{NPM, PyPI, Maven, NuGet, RubyGems, Packagist, Crates, Go, VSCode, OpenVSX, Skills, Brew}

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
