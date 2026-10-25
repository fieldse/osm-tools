package parser_test

import "testing"

// AT-3.1, AT-3.2: package.json range specs (caret, tilde, comparators,
// x-ranges, star, dist-tags, hyphen and || ranges) parse with Version "".
// workspace:, file:, git and tarball specs are either skipped or Version "".
func TestAcceptancePackageJSONRangesHaveNoVersion(t *testing.T) {
	got := mustParse(t, acceptanceDir+"r3-packagejson-ranges/package.json")

	want := []nv{
		{"axios", ""},         // ^1.14.0
		{"tilde-dep", ""},     // ~1.2.3
		{"gte-dep", ""},       // >=1.0.0
		{"x-range-dep", ""},   // 1.x
		{"x-patch-dep", ""},   // 1.2.x
		{"star-dep", ""},      // *
		{"latest-dep", ""},    // latest
		{"hyphen-dep", ""},    // 1.2.3 - 2.0.0
		{"or-dep", ""},        // ^1 || ^2
		{"lt-dep", ""},        // <2.0.0
		{"and-dep", ""},       // >1.0.0 <2.0.0
		{"dev-caret-dep", ""}, // ^3.2.0 (devDependencies)
		{"dev-tilde-dep", ""}, // ~5.6.0 (devDependencies)
	}
	local := []string{"workspace-dep", "file-dep", "git-dep", "tarball-dep"}
	assertExactDeps(t, got, want, local)
}

// AT-3.3: exact package.json versions are kept; a leading "=" is stripped and
// prerelease tags survive, in both dependencies and devDependencies.
func TestAcceptancePackageJSONExactVersionsKept(t *testing.T) {
	got := mustParse(t, acceptanceDir+"r3-packagejson-exact/package.json")

	want := []nv{
		{"exact-plain", "1.2.3"},
		{"exact-eq", "1.2.3"},
		{"exact-pre", "1.2.3-beta.1"},
		{"dev-exact-plain", "4.17.21"},
		{"dev-exact-eq", "29.7.0"},
		{"dev-exact-pre", "5.0.0-rc.2"},
	}
	assertExactDeps(t, got, want, nil)
}

// AT-3.4: npm aliases ("local": "npm:real@spec") resolve to the real package
// name, with the version following the same exact/range rules; the alias key
// itself is never returned.
func TestAcceptancePackageJSONAliasResolved(t *testing.T) {
	got := mustParse(t, acceptanceDir+"r3-packagejson-alias/package.json")

	want := []nv{
		{"axios", "1.14.1"},      // my-axios: npm:axios@1.14.1
		{"@scope/real", "2.0.0"}, // scoped-alias: npm:@scope/real@2.0.0
		{"string-width", ""},     // ranged-alias: npm:string-width@^4.2.0
		{"lodash", "4.17.21"},    // dev-alias: npm:lodash@4.17.21
	}
	assertExactDeps(t, got, want, nil)
	for _, p := range got {
		switch p.Name {
		case "my-axios", "scoped-alias", "ranged-alias", "dev-alias":
			t.Errorf("alias key %q returned as a package name; want the real name", p.Name)
		}
	}
}

// AT-3.6: a package-lock.json root dep with no node_modules/<name> entry falls
// back to its spec with the range rules applied; resolved entries keep the
// installed version and transitive-only entries are not returned.
func TestAcceptancePackageLockMissingEntryFallsBackToSpec(t *testing.T) {
	got := mustParse(t, acceptanceDir+"r3-packagelock-fallback/package-lock.json")

	want := []nv{
		{"resolved-dep", "4.17.21"}, // node_modules entry present
		{"dev-resolved", "29.7.0"},  // node_modules entry present (dev)
		{"missing-caret", ""},       // ^1.14.0, no entry
		{"missing-exact", "2.0.0"},  // 2.0.0, no entry
		{"missing-eq", "3.1.0"},     // =3.1.0, no entry
		{"missing-tilde", ""},       // ~5.6.0, no entry (dev)
		{"missing-star", ""},        // *, no entry (dev)
	}
	assertExactDeps(t, got, want, []string{"missing-git"})
}
