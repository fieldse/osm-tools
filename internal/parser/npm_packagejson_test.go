package parser

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/fieldse/osm-tools/internal/ecosystem"
)

func TestParsePackageJSON(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []Package
		wantErr bool
	}{
		{
			// Ranges carry no exact version, so only lodash keeps one (R3).
			name: "dependencies and devDependencies merged and sorted",
			path: "testdata/pkg_basic.json",
			want: []Package{
				{Name: "eslint", Version: "", Ecosystem: ecosystem.NPM},
				{Name: "express", Version: "", Ecosystem: ecosystem.NPM},
				{Name: "lodash", Version: "4.17.21", Ecosystem: ecosystem.NPM},
				{Name: "typescript", Version: "", Ecosystem: ecosystem.NPM},
			},
		},
		{
			name: "missing devDependencies",
			path: "testdata/pkg_no_dev.json",
			want: []Package{
				{Name: "react", Version: "", Ecosystem: ecosystem.NPM},
			},
		},
		{
			name: "no dependency keys yields empty slice",
			path: "testdata/pkg_empty.json",
			want: []Package{},
		},
		{
			name:    "malformed JSON returns error",
			path:    "testdata/pkg_malformed.json",
			wantErr: true,
		},
		{
			name:    "missing file returns error",
			path:    "testdata/does_not_exist.json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePackageJSON(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePackageJSON(%q) = nil error, want error", tt.path)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePackageJSON(%q) unexpected error: %v", tt.path, err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("parsePackageJSON(%q) returned %d packages, want %d: %+v", tt.path, len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("package[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestParsePackageJSONSorted guards the determinism contract independently of
// the fixture ordering above.
func TestParsePackageJSONSorted(t *testing.T) {
	got, err := parsePackageJSON("testdata/pkg_basic.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].Name < got[j].Name }) {
		t.Errorf("result is not sorted by Name: %+v", got)
	}
}

// TestOptionalDependenciesAreDirect: npm and yarn install optionalDependencies
// by default, so every npm format returns them as direct deps.
func TestOptionalDependenciesAreDirect(t *testing.T) {
	const pkgJSON = `{"dependencies":{"axios":"1.14.1"},"optionalDependencies":{"evil-pkg":"^1.0.0"}}`
	tests := []struct {
		name     string
		manifest string
		files    map[string]string
		want     []Package
	}{
		{
			name:     "package.json",
			manifest: "package.json",
			files:    map[string]string{"package.json": pkgJSON},
			want: []Package{
				{Name: "axios", Version: "1.14.1", Ecosystem: ecosystem.NPM},
				{Name: "evil-pkg", Version: "", Ecosystem: ecosystem.NPM},
			},
		},
		{
			name:     "package-lock.json",
			manifest: "package-lock.json",
			files: map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{
				"":{"dependencies":{"axios":"1.14.1"},"optionalDependencies":{"evil-pkg":"^1.0.0"}},
				"node_modules/axios":{"version":"1.14.1"},
				"node_modules/evil-pkg":{"version":"1.0.0","optional":true}}}`},
			want: []Package{
				{Name: "axios", Version: "1.14.1", Ecosystem: ecosystem.NPM},
				{Name: "evil-pkg", Version: "1.0.0", Ecosystem: ecosystem.NPM},
			},
		},
		{
			name:     "yarn.lock v1",
			manifest: "yarn.lock",
			files: map[string]string{
				"package.json": pkgJSON,
				"yarn.lock":    "# yarn lockfile v1\n\naxios@1.14.1:\n  version \"1.14.1\"\n\nevil-pkg@^1.0.0:\n  version \"1.0.0\"\n",
			},
			want: []Package{
				{Name: "axios", Version: "1.14.1", Ecosystem: ecosystem.NPM},
				{Name: "evil-pkg", Version: "1.0.0", Ecosystem: ecosystem.NPM},
			},
		},
		{
			name:     "yarn.lock berry",
			manifest: "yarn.lock",
			files: map[string]string{
				"package.json": pkgJSON,
				"yarn.lock": "__metadata:\n  version: 8\n\n\"axios@npm:1.14.1\":\n  version: 1.14.1\n\n" +
					"\"evil-pkg@npm:^1.0.0\":\n  version: 1.0.0\n",
			},
			want: []Package{
				{Name: "axios", Version: "1.14.1", Ecosystem: ecosystem.NPM},
				{Name: "evil-pkg", Version: "1.0.0", Ecosystem: ecosystem.NPM},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tt.files {
				writeFile(t, dir, name, body)
			}
			got, err := Parse(filepath.Join(dir, tt.manifest))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
