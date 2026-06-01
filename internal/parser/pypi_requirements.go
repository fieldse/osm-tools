package parser

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// exactPinSep is the only specifier we record as a Version; any other
// comparison operator pins a range, which we leave empty.
const exactPinSep = "=="

// nonExactSpecifiers are the comparison operators that pin a range rather than
// an exact version. When one is present we capture the name but leave Version
// empty. Order matters: longer operators are checked before their single-char
// prefixes so that ">=" is not mistaken for ">".
var nonExactSpecifiers = []string{">=", "<=", "~=", "!=", "===", ">", "<"}

// parseRequirements reads a pip requirements.txt file and returns its direct
// dependencies. Only file-read failures are returned as errors; malformed
// individual lines are skipped so a single junk line cannot abort the parse.
func parseRequirements(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open requirements file %q: %w", path, err)
	}
	defer f.Close()

	var pkgs []Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if pkg, ok := parseRequirementLine(sc.Text()); ok {
			pkgs = append(pkgs, pkg)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read requirements file %q: %w", path, err)
	}

	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	return pkgs, nil
}

// parseRequirementLine parses a single requirements.txt line into a Package.
// The bool is false when the line carries no package (blank, comment, option,
// or unparseable).
func parseRequirementLine(line string) (Package, bool) {
	// Strip trailing inline comments, then surrounding whitespace.
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return Package{}, false
	}

	// Skip option lines and includes: -r, -c, -e, --hash, etc.
	if strings.HasPrefix(line, "-") {
		return Package{}, false
	}

	// Drop environment markers (everything after ';').
	if i := strings.Index(line, ";"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}

	// Split name (with optional extras) from the version specifier.
	name, version := splitNameSpecifier(line)

	// Strip extras in brackets: requests[security] -> requests.
	if i := strings.Index(name, "["); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Package{}, false
	}

	return Package{Name: name, Version: version, Ecosystem: EcosystemPyPI}, true
}

// splitNameSpecifier separates the package name from its version specifier.
// It returns the version only for an exact (==) pin; every other specifier
// yields an empty version. A bare name yields an empty version.
func splitNameSpecifier(line string) (name, version string) {
	// Exact pin wins: capture the version after ==.
	if i := strings.Index(line, exactPinSep); i >= 0 {
		name = line[:i]
		version = strings.TrimSpace(line[i+len(exactPinSep):])
		// A trailing range op (e.g. "==1.0,>=0.9") is not an exact pin.
		if j := strings.IndexAny(version, ",;"); j >= 0 {
			version = strings.TrimSpace(version[:j])
		}
		return name, version
	}

	// Any other comparison operator: name only, empty version.
	for _, op := range nonExactSpecifiers {
		if i := strings.Index(line, op); i >= 0 {
			return line[:i], ""
		}
	}

	// Bare name, no specifier.
	return line, ""
}
