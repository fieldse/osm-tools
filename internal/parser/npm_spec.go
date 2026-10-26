package parser

import (
	"regexp"
	"strings"
)

// npmExact matches one full semver version, with optional prerelease and
// build metadata. Anything else in a spec is a range, tag or partial version.
var npmExact = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// npmExactVersion returns the version a spec pins, or "" when the spec is a
// range, dist-tag or partial version. A leading "=" or "v" is dropped.
func npmExactVersion(spec string) string {
	v := strings.TrimSpace(spec)
	v = strings.TrimSpace(strings.TrimPrefix(v, "="))
	v = strings.TrimPrefix(v, "v")
	if npmExact.MatchString(v) {
		return v
	}
	return ""
}

// npmSpec resolves a dependency entry to the registry name to look up and the
// exact version it pins ("" for a range). An npm alias ("npm:real@spec")
// resolves to the real name. ok is false for specs that do not come from the
// registry: workspace:, file:, link:, git, tarball URLs and paths.
func npmSpec(name, spec string) (pkgName, version string, ok bool) {
	spec = strings.TrimSpace(spec)
	if target, isAlias := strings.CutPrefix(spec, "npm:"); isAlias {
		name, spec = target, ""
		if i := strings.LastIndex(target, "@"); i > 0 {
			name, spec = target[:i], target[i+1:]
		}
	}
	if name == "" || strings.ContainsAny(spec, ":/") {
		return "", "", false
	}
	return name, npmExactVersion(spec), true
}
