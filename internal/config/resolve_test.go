package config

import (
	"errors"
	"testing"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

func TestResolveToken(t *testing.T) {
	tests := []struct {
		name            string
		flag, env, file string
		want            string
		wantErr         bool
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

func TestResolveContactEmail(t *testing.T) {
	tests := []struct {
		name, report, file, want string
	}{
		{"report wins over config", "report@example.com", "cfg@example.com", "report@example.com"},
		{"config fills a missing report email", "", "cfg@example.com", "cfg@example.com"},
		{"whitespace report email counts as missing", "  ", "cfg@example.com", "cfg@example.com"},
		{"neither set stays empty", "", "", ""},
		{"report email only", "report@example.com", "", "report@example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveContactEmail(tt.report, tt.file); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
