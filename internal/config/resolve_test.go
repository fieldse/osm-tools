package config

import (
	"errors"
	"testing"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

func TestResolveToken(t *testing.T) {
	tests := []struct {
		name              string
		flag, env, file   string
		want              string
		wantErr           bool
	}{
		{"flag wins over all", "flagtok", "envtok", "filetok", "flagtok", false},
		{"env wins over file", "", "envtok", "filetok", "envtok", false},
		{"file used when only source", "", "", "filetok", "filetok", false},
		{"all empty is ErrNoToken", "", "", "", "", true},
		{"whitespace flag is skipped", "   ", "envtok", "", "envtok", false},
		{"whitespace-only everywhere errors", "  ", "\t", " ", "", true},
		{"token is trimmed", "  flagtok  ", "", "", "flagtok", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveToken(tt.flag, tt.env, tt.file)
			if tt.wantErr {
				if !errors.Is(err, osmerr.ErrNoToken) {
					t.Fatalf("want ErrNoToken, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
