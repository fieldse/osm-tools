package report

import (
	"fmt"
	"time"

	"github.com/fieldse/osm-tools/internal/ecosystem"
	"github.com/fieldse/osm-tools/internal/osmerr"
)

// validSeverities is the accepted severity_level vocabulary (warn-only).
var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// Validate performs structural validation of a report — never content or style
// judgement. Missing required fields (Type, ResourceID, Description) or an
// invalid Type return a *osmerr.UsageError (exit 2). Softer problems — an
// unrecognized Registry, a malformed SeverityLevel, a non-ISO-8601
// FirstSeen/LastSeen, or a blank optional field — are returned as human-readable
// warnings with a nil error, to be surfaced on stderr without blocking.
//
// Registry values are checked against internal/ecosystem's vocabulary (warn
// only); the report_type enum is checked against IsValidType (hard error).
func Validate(r Report) (warnings []string, err error) {
	// Hard errors: report the first missing/invalid required field, in order.
	switch {
	case r.Type == "":
		return nil, osmerr.Usagef("report_type is required")
	case !IsValidType(r.Type):
		return nil, osmerr.Usagef("invalid report_type %q; must be one of package|container|repository|url|domain|ip|wallet (or docker)", r.Type)
	case r.ResourceID == "":
		return nil, osmerr.Usagef("resource_identifier is required")
	case r.Description == "":
		return nil, osmerr.Usagef("threat_description is required")
	}

	// Soft problems: collect as warnings, never block.
	if r.Registry != "" && !ecosystem.IsValid(r.Registry) {
		warnings = append(warnings, fmt.Sprintf("unrecognized registry %q", r.Registry))
	}
	if r.SeverityLevel != "" && !validSeverities[r.SeverityLevel] {
		warnings = append(warnings, fmt.Sprintf("unrecognized severity_level %q", r.SeverityLevel))
	}
	if r.FirstSeen != "" && !isRFC3339(r.FirstSeen) {
		warnings = append(warnings, fmt.Sprintf("first_seen is not ISO 8601: %q", r.FirstSeen))
	}
	if r.LastSeen != "" && !isRFC3339(r.LastSeen) {
		warnings = append(warnings, fmt.Sprintf("last_seen is not ISO 8601: %q", r.LastSeen))
	}

	return warnings, nil
}

// isRFC3339 reports whether v parses as an RFC 3339 (ISO 8601) timestamp.
func isRFC3339(v string) bool {
	_, err := time.Parse(time.RFC3339, v)
	return err == nil
}
