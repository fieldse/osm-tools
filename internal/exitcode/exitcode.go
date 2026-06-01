// Package exitcode is the single source of truth for mapping command errors to
// process exit codes.
//
// Codes:
//
//	0 — success / clean run
//	1 — operational failure (network, 5xx, auth, unreadable manifest, API unreachable)
//	2 — usage error (bad flags, missing/unknown ecosystem)
//	3 — sweep gate triggered (--fail-on-any with at least one malicious hit)
package exitcode

import (
	"errors"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

const (
	OK          = 0
	Operational = 1
	Usage       = 2
	Gate        = 3
)

// FromError maps an error returned by a command's RunE to an exit code. A nil
// error is success.
func FromError(err error) int {
	if err == nil {
		return OK
	}

	// Policy verdict, not a failure: the sweep gate fired.
	var gate *osmerr.GateTriggered
	if errors.As(err, &gate) {
		return Gate
	}

	// User-input problems.
	var usage *osmerr.UsageError
	if errors.As(err, &usage) {
		return Usage
	}

	// Everything else — API errors, network failures, missing token, decode
	// errors — is operational.
	return Operational
}
