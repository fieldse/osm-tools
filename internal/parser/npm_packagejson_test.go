package parser

import (
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
			name: "dependencies and devDependencies merged and sorted",
			path: "testdata/pkg_basic.json",
			want: []Package{
				{Name: "eslint", Version: "^9.0.0", Ecosystem: ecosystem.NPM},
				{Name: "express", Version: "^4.18.2", Ecosystem: ecosystem.NPM},
				{Name: "lodash", Version: "4.17.21", Ecosystem: ecosystem.NPM},
				{Name: "typescript", Version: "~5.4.0", Ecosystem: ecosystem.NPM},
			},
		},
		{
			name: "missing devDependencies",
			path: "testdata/pkg_no_dev.json",
			want: []Package{
				{Name: "react", Version: "^18.2.0", Ecosystem: ecosystem.NPM},
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
