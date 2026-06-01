package parser

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestParsePackageLock(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    []Package
		wantErr bool
	}{
		{
			name: "v3 returns only direct deps with resolved versions",
			file: "lock_v3.json",
			// accepts/mime-types are transitive and excluded; express/lodash/jest
			// resolve from node_modules; leftpad falls back to spec. Sorted.
			want: []Package{
				{Name: "express", Version: "4.18.2", Ecosystem: EcosystemNPM},
				{Name: "jest", Version: "29.7.0", Ecosystem: EcosystemNPM},
				{Name: "leftpad", Version: "^1.0.0", Ecosystem: EcosystemNPM},
				{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNPM},
			},
		},
		{
			name: "v1 takes top-level dependencies map",
			file: "lock_v1.json",
			want: []Package{
				{Name: "express", Version: "4.18.2", Ecosystem: EcosystemNPM},
				{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNPM},
			},
		},
		{
			name:    "malformed JSON returns error",
			file:    "lock_malformed.json",
			wantErr: true,
		},
		{
			name:    "missing file returns error",
			file:    "does_not_exist.json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePackageLock(filepath.Join("testdata", tt.file))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePackageLock() mismatch\n got: %+v\nwant: %+v", got, tt.want)
			}
		})
	}
}

func TestParsePackageLockSorted(t *testing.T) {
	got, err := parsePackageLock(filepath.Join("testdata", "lock_v3.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Name > got[i].Name {
			t.Errorf("output not sorted by Name: %q before %q", got[i-1].Name, got[i].Name)
		}
	}
}
