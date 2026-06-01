package parser

import (
	"sort"
	"testing"

	"github.com/fieldse/osm-tools/internal/ecosystem"
)

func TestParsePoetryLock(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []Package
		wantErr bool
	}{
		{
			name: "multiple package entries parsed and sorted",
			path: "testdata/poetry_basic.lock",
			want: []Package{
				{Name: "click", Version: "8.1.7", Ecosystem: ecosystem.PyPI},
				{Name: "requests", Version: "2.31.0", Ecosystem: ecosystem.PyPI},
				{Name: "urllib3", Version: "2.0.7", Ecosystem: ecosystem.PyPI},
			},
		},
		{
			name: "no package entries yields empty slice",
			path: "testdata/poetry_empty.lock",
			want: []Package{},
		},
		{
			name:    "malformed TOML returns error",
			path:    "testdata/poetry_malformed.lock",
			wantErr: true,
		},
		{
			name:    "missing file returns error",
			path:    "testdata/does_not_exist.lock",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePoetryLock(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePoetryLock(%q) = nil error, want error", tt.path)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePoetryLock(%q) unexpected error: %v", tt.path, err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("parsePoetryLock(%q) returned %d packages, want %d: %+v", tt.path, len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("package[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestParsePoetryLockSorted guards the determinism contract independently of
// the fixture ordering above.
func TestParsePoetryLockSorted(t *testing.T) {
	got, err := parsePoetryLock("testdata/poetry_basic.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].Name < got[j].Name }) {
		t.Errorf("result is not sorted by Name: %+v", got)
	}
}
