// Package osmerr defines the error vocabulary shared across the osm CLI.
//
// Commands return these errors from their RunE functions; a single mapper in
// main translates them to process exit codes. Keeping the taxonomy small and
// typed lets the mapper branch with errors.Is / errors.As rather than string
// matching.
package osmerr

import (
	"errors"
	"fmt"
)

// Sentinel errors. Compare with errors.Is.
var (
	// ErrNoToken means no API token could be resolved from any source
	// (--token flag, OSM_API_KEY env, or config file).
	ErrNoToken = errors.New("no API token configured")

	// ErrNotFound means the API reported the resource as unknown.
	ErrNotFound = errors.New("resource not found")
)

// APIError is a non-2xx response from the OSM API. Callers classify on
// StatusCode (401 → auth, 429 → rate-limit, 5xx → server).
type APIError struct {
	StatusCode int
	Body       string
	// RetryAfter is the parsed Retry-After header for 429s, if present.
	RetryAfter string
}

func (e *APIError) Error() string {
	if e.RetryAfter != "" {
		return fmt.Sprintf("API error: status %d (retry after %s): %s", e.StatusCode, e.RetryAfter, e.Body)
	}
	return fmt.Sprintf("API error: status %d: %s", e.StatusCode, e.Body)
}

// UsageError is a user-input problem: bad flag, unknown ecosystem, unreadable
// or unrecognized manifest. It maps to exit code 2. The message should carry
// the remedy.
type UsageError struct {
	Msg string
}

func (e *UsageError) Error() string { return e.Msg }

// Usagef builds a UsageError with a formatted message.
func Usagef(format string, args ...any) *UsageError {
	return &UsageError{Msg: fmt.Sprintf(format, args...)}
}

// GateTriggered signals that `sweep --fail-on-any` found at least one malicious
// result. It is a successful run with a policy verdict, not an error condition;
// the mapper recognizes it and returns exit code 3. Hits carries the offending
// package identifiers for the summary line.
type GateTriggered struct {
	Hits []string
}

func (e *GateTriggered) Error() string {
	return fmt.Sprintf("policy gate triggered: %d malicious package(s) found", len(e.Hits))
}
