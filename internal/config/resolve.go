package config

import (
	"strings"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// ResolveToken returns the active token, applying precedence:
// --token flag > OSM_API_KEY env > config-file token.
//
// It is deliberately pure — callers pass the values in, so precedence is
// table-testable without touching the environment or filesystem.
// All three empty returns ErrNoToken.
func ResolveToken(flag, env, fileToken string) (string, error) {
	for _, v := range []string{flag, env, fileToken} {
		if t := strings.TrimSpace(v); t != "" {
			return t, nil
		}
	}
	return "", osmerr.ErrNoToken
}
