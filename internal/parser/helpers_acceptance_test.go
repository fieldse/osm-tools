package parser_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/parser"
)

const acceptanceDir = "testdata/acceptance/"

// nv is a name+version pair; ecosystem is checked separately (AT-12.14).
type nv struct {
	Name    string
	Version string
}

func (p nv) String() string { return fmt.Sprintf("%s@%q", p.Name, p.Version) }

// mustParse calls parser.Parse and fails the test on error.
func mustParse(t *testing.T, path string) []parser.Package {
	t.Helper()
	pkgs, err := parser.Parse(path)
	if err != nil {
		t.Fatalf("Parse(%q) returned error: %v", path, err)
	}
	return pkgs
}

func describe(pkgs []parser.Package) string {
	parts := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		parts = append(parts, nv{p.Name, p.Version}.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// assertExactDeps checks that got holds every entry of want exactly once and
// nothing else, except names listed in local (link:, file:, workspace:, git or
// tarball deps), which may be absent or present once with an empty Version.
func assertExactDeps(t *testing.T, got []parser.Package, want []nv, local []string) {
	t.Helper()
	isLocal := make(map[string]bool, len(local))
	for _, n := range local {
		isLocal[n] = true
	}
	wantSet := make(map[nv]bool, len(want))
	for _, w := range want {
		wantSet[w] = true
	}

	counts := make(map[nv]int)
	localCounts := make(map[string]int)
	for _, p := range got {
		k := nv{p.Name, p.Version}
		if isLocal[p.Name] {
			localCounts[p.Name]++
			if p.Version != "" {
				t.Errorf("local dep %s returned with a version; want it skipped or with Version \"\"", k)
			}
			continue
		}
		counts[k]++
		if !wantSet[k] {
			t.Errorf("unexpected package %s", k)
		}
	}
	for _, w := range want {
		switch n := counts[w]; {
		case n == 0:
			t.Errorf("missing package %s", w)
		case n > 1:
			t.Errorf("package %s returned %d times, want once", w, n)
		}
	}
	for name, n := range localCounts {
		if n > 1 {
			t.Errorf("local dep %q returned %d times, want at most once", name, n)
		}
	}
	if t.Failed() {
		t.Logf("got: %s", describe(got))
	}
}
