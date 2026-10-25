package parser_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/exitcode"
	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/fieldse/osm-tools/internal/parser"
)

const (
	pnpmV9Single   = acceptanceDir + "pnpm-v9-single/pnpm-lock.yaml"
	pnpmV9Monorepo = acceptanceDir + "pnpm-v9-monorepo/pnpm-lock.yaml"
	pnpmV6Single   = acceptanceDir + "pnpm-v6-single/pnpm-lock.yaml"
	pnpmV6Monorepo = acceptanceDir + "pnpm-v6-monorepo/pnpm-lock.yaml"
	yarnV1         = acceptanceDir + "yarn-v1/yarn.lock"
	yarnBerry      = acceptanceDir + "yarn-berry/yarn.lock"
)

var (
	pnpmV9SingleWant = []nv{
		{"@scope/pkg", "2.1.0"},
		{"axios", "1.14.1"},
		{"@scope/real", "1.0.0"}, // my-scoped-alias -> '@scope/real@1.0.0'
		{"react", "18.3.1"},
		{"react-dom", "18.3.1"},    // 18.3.1(react@18.3.1)
		{"string-width", "4.2.3"},  // string-width-cjs -> string-width@4.2.3
		{"@types/node", "22.20.0"}, // devDependencies
		{"jsdom", "25.0.1"},        // devDependencies
		{"typescript", "5.6.3"},    // devDependencies
		{"vitest", "3.2.7"},        // devDependencies, two peer suffixes
		{"fsevents", "2.3.3"},      // optionalDependencies
	}
	pnpmV9SingleLocal = []string{"local-tarball", "my-local-lib"}

	pnpmV9MonorepoWant = []nv{
		{"prettier", "3.3.3"},
		{"typescript", "5.6.3"}, // in all three importers
		{"next", "15.0.3"},      // nested peer suffix
		{"react", "18.3.1"},
		{"react-dom", "18.3.1"},
		{"zod", "3.23.8"}, // apps/web
		{"zod", "3.24.1"}, // packages/shared
		{"lodash", "4.17.21"},
		{"@types/lodash", "4.17.13"},
	}
	pnpmV9MonorepoLocal = []string{"@acme/shared"}

	pnpmV6SingleWant = []nv{
		{"@scope/pkg", "2.1.0"},
		{"axios", "1.14.1"},
		{"string-width", "4.2.3"}, // string-width-cjs -> /string-width@4.2.3
		{"@types/node", "22.20.0"},
		{"vitest", "3.2.7"}, // 3.2.7(@types/node@22.20.0)
		{"fsevents", "2.3.3"},
	}
	pnpmV6SingleLocal = []string{"my-local-lib"}

	pnpmV6MonorepoWant = []nv{
		{"typescript", "5.6.3"},
		{"lodash", "4.17.21"}, // in packages/a and packages/b
		{"chalk", "5.3.0"},
	}
	pnpmV6MonorepoLocal = []string{"@acme/b"}

	// yarnWant is the same for v1 and berry: the sibling package.json lists
	// these six, and each resolves through its name@spec lock entry. debug and
	// chalk each have a transitive entry before or after the direct one, so
	// resolving by name alone picks the wrong version for one of them.
	yarnWant = []nv{
		{"@scope/pkg", "2.1.0"}, // second spec of a multi-spec quoted key
		{"axios", "1.14.1"},
		{"debug", "2.6.9"},      // debug@^4.3.4 -> 4.3.7 is transitive
		{"lodash", "4.17.21"},   // second spec of a multi-spec key
		{"chalk", "4.1.2"},      // chalk@^2.4.2 -> 2.4.2 is transitive
		{"typescript", "5.6.3"}, // berry also has a patch: entry
	}
)

// AT-12.1: a pnpm v9 lockfile with a single "." importer returns its direct
// dependencies, devDependencies and optionalDependencies with exact versions,
// and nothing else.
func TestAcceptancePnpmV9SingleImporter(t *testing.T) {
	assertExactDeps(t, mustParse(t, pnpmV9Single), pnpmV9SingleWant, pnpmV9SingleLocal)
}

// AT-12.2: pnpm peer suffixes, including nested ones, are stripped from the
// version in v9 and v6 lockfiles.
func TestAcceptancePnpmPeerSuffixStripped(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []nv
	}{
		{"v9 two suffixes", pnpmV9Single, []nv{{"vitest", "3.2.7"}, {"react-dom", "18.3.1"}}},
		{"v9 nested suffix", pnpmV9Monorepo, []nv{{"next", "15.0.3"}, {"react-dom", "18.3.1"}}},
		{"v6 suffix", pnpmV6Single, []nv{{"vitest", "3.2.7"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustParse(t, tt.path)
			for _, w := range tt.want {
				if !containsExactlyOnce(got, w) {
					t.Errorf("want %s exactly once; got: %s", w, describe(got))
				}
			}
			for _, p := range got {
				if strings.ContainsAny(p.Version, "()") {
					t.Errorf("%s still carries a peer suffix", nv{p.Name, p.Version})
				}
			}
		})
	}
}

// AT-12.3: a pnpm monorepo lockfile returns the union of every importer's
// direct deps, with identical name+version pairs collapsed and distinct
// versions of one name kept (v9 and v6 importers formats).
func TestAcceptancePnpmMonorepoUnion(t *testing.T) {
	t.Run("v9", func(t *testing.T) {
		assertExactDeps(t, mustParse(t, pnpmV9Monorepo), pnpmV9MonorepoWant, pnpmV9MonorepoLocal)
	})
	t.Run("v6", func(t *testing.T) {
		assertExactDeps(t, mustParse(t, pnpmV6Monorepo), pnpmV6MonorepoWant, pnpmV6MonorepoLocal)
	})
}

// AT-12.4: pnpm link:, file: and workspace: entries never surface their local
// reference as a version; the dep is skipped or returned with Version "".
func TestAcceptancePnpmLocalVersionsSkipped(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		local  []string
		anchor nv // a registry dep that must still be returned
	}{
		{"v9 link and file", pnpmV9Single, pnpmV9SingleLocal, nv{"axios", "1.14.1"}},
		{"v9 workspace link", pnpmV9Monorepo, pnpmV9MonorepoLocal, nv{"lodash", "4.17.21"}},
		{"v6 link", pnpmV6Single, pnpmV6SingleLocal, nv{"axios", "1.14.1"}},
		{"v6 workspace link", pnpmV6Monorepo, pnpmV6MonorepoLocal, nv{"chalk", "5.3.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustParse(t, tt.path)
			if !containsExactlyOnce(got, tt.anchor) {
				t.Fatalf("registry dep %s missing; got: %s", tt.anchor, describe(got))
			}
			for _, p := range got {
				for _, prefix := range []string{"link:", "file:", "workspace:"} {
					if strings.HasPrefix(p.Version, prefix) || strings.Contains(p.Name, prefix) {
						t.Errorf("%s carries a %s reference", nv{p.Name, p.Version}, prefix)
					}
				}
				for _, l := range tt.local {
					if p.Name == l && p.Version != "" {
						t.Errorf("local dep %s returned with a version", nv{p.Name, p.Version})
					}
				}
			}
		})
	}
}

// AT-12.5: a pnpm v6 single-project lockfile (top-level dependencies,
// devDependencies, optionalDependencies; "/name@ver" package keys) parses the
// same way as v9.
func TestAcceptancePnpmV6SingleProject(t *testing.T) {
	assertExactDeps(t, mustParse(t, pnpmV6Single), pnpmV6SingleWant, pnpmV6SingleLocal)
}

// AT-12.6: a pnpm alias (key differs from the "name@version" in version)
// resolves to the real name and version, for unscoped and scoped targets in
// v9 and for v6's leading-slash form; the alias key is never returned.
func TestAcceptancePnpmAliasResolved(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		want      []nv
		aliasKeys []string
	}{
		{"v9", pnpmV9Single, []nv{{"string-width", "4.2.3"}, {"@scope/real", "1.0.0"}}, []string{"string-width-cjs", "my-scoped-alias"}},
		{"v6", pnpmV6Single, []nv{{"string-width", "4.2.3"}}, []string{"string-width-cjs"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustParse(t, tt.path)
			for _, w := range tt.want {
				if !containsExactlyOnce(got, w) {
					t.Errorf("want %s exactly once; got: %s", w, describe(got))
				}
			}
			for _, p := range got {
				for _, k := range tt.aliasKeys {
					if p.Name == k {
						t.Errorf("alias key %q returned as a package name", k)
					}
				}
				if strings.Contains(p.Version, "@") || strings.HasPrefix(p.Version, "/") {
					t.Errorf("%s: version still holds a name@version reference", nv{p.Name, p.Version})
				}
			}
		})
	}
}

// AT-12.7: scoped names come back intact (quotes removed, scope kept) from
// pnpm v9, pnpm v6, yarn v1 and yarn berry.
func TestAcceptanceLockfileScopedNamesKept(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []nv
	}{
		{"pnpm v9", pnpmV9Single, []nv{{"@scope/pkg", "2.1.0"}, {"@types/node", "22.20.0"}}},
		{"pnpm v9 monorepo", pnpmV9Monorepo, []nv{{"@types/lodash", "4.17.13"}}},
		{"pnpm v6", pnpmV6Single, []nv{{"@scope/pkg", "2.1.0"}, {"@types/node", "22.20.0"}}},
		{"yarn v1", yarnV1, []nv{{"@scope/pkg", "2.1.0"}}},
		{"yarn berry", yarnBerry, []nv{{"@scope/pkg", "2.1.0"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustParse(t, tt.path)
			for _, w := range tt.want {
				if !containsExactlyOnce(got, w) {
					t.Errorf("want %s exactly once; got: %s", w, describe(got))
				}
			}
			for _, p := range got {
				if strings.ContainsAny(p.Name, `'"`) || strings.HasPrefix(p.Name, "/") {
					t.Errorf("name %q carries lockfile quoting or a leading slash", p.Name)
				}
			}
		})
	}
}

// AT-12.8: packages that appear only under packages:/snapshots: (transitive
// deps) are not returned, while the importers' direct deps are.
func TestAcceptancePnpmTransitiveNotReturned(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		anchor     nv
		transitive []string
	}{
		{"v9", pnpmV9Single, nv{"axios", "1.14.1"}, []string{
			"follow-redirects", "form-data", "proxy-from-env", "asynckit", "ansi-regex",
			"emoji-regex", "strip-ansi", "scheduler", "loose-envify", "js-tokens",
			"undici-types", "@vitest/expect",
		}},
		{"v9 monorepo", pnpmV9Monorepo, nv{"next", "15.0.3"}, []string{
			"@next/env", "scheduler", "loose-envify", "js-tokens",
		}},
		{"v6", pnpmV6Single, nv{"axios", "1.14.1"}, []string{
			"follow-redirects", "proxy-from-env", "ansi-regex", "emoji-regex",
			"strip-ansi", "undici-types", "@vitest/expect",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustParse(t, tt.path)
			if !containsExactlyOnce(got, tt.anchor) {
				t.Fatalf("direct dep %s missing; got: %s", tt.anchor, describe(got))
			}
			for _, p := range got {
				for _, tr := range tt.transitive {
					if p.Name == tr {
						t.Errorf("transitive-only package %s returned", nv{p.Name, p.Version})
					}
				}
			}
		})
	}
}

// AT-12.9: yarn v1 with a sibling package.json returns only the package.json
// direct deps, each resolved through its matching name@spec entry, including
// a spec that is the second of a multi-spec key. Works for relative and
// absolute paths.
func TestAcceptanceYarnV1DirectDeps(t *testing.T) {
	t.Run("relative path", func(t *testing.T) {
		assertExactDeps(t, mustParse(t, yarnV1), yarnWant, nil)
	})
	t.Run("absolute path in another directory", func(t *testing.T) {
		dir := copyFixtureDir(t, filepath.Dir(yarnV1))
		assertExactDeps(t, mustParse(t, filepath.Join(dir, "yarn.lock")), yarnWant, nil)
	})
}

// AT-12.10: yarn berry (__metadata:) with a sibling package.json resolves
// direct deps through "name@npm:spec" entries, ignoring the workspace entry
// and patch: entries.
func TestAcceptanceYarnBerryDirectDeps(t *testing.T) {
	t.Run("relative path", func(t *testing.T) {
		assertExactDeps(t, mustParse(t, yarnBerry), yarnWant, nil)
	})
	t.Run("absolute path in another directory", func(t *testing.T) {
		dir := copyFixtureDir(t, filepath.Dir(yarnBerry))
		assertExactDeps(t, mustParse(t, filepath.Join(dir, "yarn.lock")), yarnWant, nil)
	})
}

// AT-12.11: a yarn.lock (v1 or berry) with no sibling package.json is an
// operational error (exit 1), not a usage error and not success.
func TestAcceptanceYarnWithoutPackageJSONIsOperationalError(t *testing.T) {
	for _, path := range []string{
		acceptanceDir + "yarn-v1-no-pkgjson/yarn.lock",
		acceptanceDir + "yarn-berry-no-pkgjson/yarn.lock",
	} {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			pkgs, err := parser.Parse(path)
			if err == nil {
				t.Fatalf("Parse(%q) returned nil error and %d packages; want an error", path, len(pkgs))
			}
			if got := exitcode.FromError(err); got != exitcode.Operational {
				t.Errorf("exit code = %d, want %d (operational); err: %v", got, exitcode.Operational, err)
			}
		})
	}
}

// AT-12.12: a pnpm-lock.yaml that is not valid YAML is an operational error
// (exit 1).
func TestAcceptancePnpmMalformedIsOperationalError(t *testing.T) {
	for _, path := range []string{
		acceptanceDir + "pnpm-malformed-unclosed/pnpm-lock.yaml",
		acceptanceDir + "pnpm-malformed-tabs/pnpm-lock.yaml",
	} {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			pkgs, err := parser.Parse(path)
			if err == nil {
				t.Fatalf("Parse(%q) returned nil error and %d packages; want an error", path, len(pkgs))
			}
			if got := exitcode.FromError(err); got != exitcode.Operational {
				t.Errorf("exit code = %d, want %d (operational); err: %v", got, exitcode.Operational, err)
			}
		})
	}
}

// AT-12.13: an unrecognised manifest name is a UsageError whose message lists
// every supported manifest, including pnpm-lock.yaml and yarn.lock.
func TestAcceptanceUnknownManifestListsAllSupported(t *testing.T) {
	supported := []string{
		"package.json", "package-lock.json", "requirements.txt", "poetry.lock",
		"pnpm-lock.yaml", "yarn.lock",
	}
	for _, name := range []string{"Cargo.lock", "Gemfile.lock", "yarn.lock.bak"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := parser.Parse(path)
			var usage *osmerr.UsageError
			if !errors.As(err, &usage) {
				t.Fatalf("Parse(%q) error = %v (%T), want *osmerr.UsageError", name, err, err)
			}
			for _, s := range supported {
				if !strings.Contains(usage.Error(), s) {
					t.Errorf("usage message %q does not list %q", usage.Error(), s)
				}
			}
		})
	}
}

// AT-12.14: every package parsed from pnpm-lock.yaml and yarn.lock has
// ecosystem "npm".
func TestAcceptanceLockfileEcosystemIsNPM(t *testing.T) {
	for _, path := range []string{pnpmV9Single, pnpmV9Monorepo, pnpmV6Single, pnpmV6Monorepo, yarnV1, yarnBerry} {
		t.Run(path, func(t *testing.T) {
			got := mustParse(t, path)
			if len(got) == 0 {
				t.Fatal("Parse returned no packages")
			}
			for _, p := range got {
				if p.Ecosystem != "npm" {
					t.Errorf("%s ecosystem = %q, want npm", nv{p.Name, p.Version}, p.Ecosystem)
				}
			}
		})
	}
}

func containsExactlyOnce(pkgs []parser.Package, want nv) bool {
	n := 0
	for _, p := range pkgs {
		if p.Name == want.Name && p.Version == want.Version {
			n++
		}
	}
	return n == 1
}

// copyFixtureDir copies the regular files of src into a fresh temp dir and
// returns its absolute path.
func copyFixtureDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}
