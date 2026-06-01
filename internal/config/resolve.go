package config

import (
	"strings"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// ResolveToken applies the token precedence rule and returns the active token.
//
// Precedence: --token flag > OSM_API_KEY env > config-file token.
//
// It is deliberately pure — callers read the flag, env, and file values and
// pass them in — so precedence is table-testable without touching the
// environment or filesystem. All three empty returns ErrNoToken.
func ResolveToken(flag, env, fileToken string) (string, error) {
	for _, v := range []string{flag, env, fileToken} {
		if t := strings.TrimSpace(v); t != "" {
			return t, nil
		}
	}
	return "", osmerr.ErrNoToken
}
