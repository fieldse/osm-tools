package exitcode

import (
	"errors"
	"fmt"
	"testing"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

func TestFromError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil is success", nil, OK},
		{"gate triggered", &osmerr.GateTriggered{Hits: []string{"evil@1.0.0"}}, Gate},
		{"usage error", osmerr.Usagef("bad flag"), Usage},
		{"no token is operational", osmerr.ErrNoToken, Operational},
		{"not found is operational", osmerr.ErrNotFound, Operational},
		{"api error is operational", &osmerr.APIError{StatusCode: 500}, Operational},
		{"plain error is operational", errors.New("boom"), Operational},
		{"wrapped gate still maps to gate", fmt.Errorf("ctx: %w", &osmerr.GateTriggered{}), Gate},
		{"wrapped usage still maps to usage", fmt.Errorf("ctx: %w", osmerr.Usagef("nope")), Usage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromError(tt.err); got != tt.want {
				t.Errorf("FromError(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
