// Package output renders command results to an io.Writer. Keeping formatting
// here (rather than in cmd) lets it be unit-tested with a buffer.
package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/termsafe"
	"github.com/fieldse/osm-tools/internal/verdict"
)

// CheckDetail renders a single check result as a human-readable block. label is
// the resource that was checked (name, domain, IP, or image reference) and
// kind is the resolved type. note, when non-empty, explains how the verdict
// was reached. Every printed string passes through termsafe, since API text
// is community-submitted.
func CheckDetail(w io.Writer, label, kind string, r client.CheckResult, status verdict.Status, note string) {
	fmt.Fprintf(w, "%s (%s)\n", termsafe.String(label), termsafe.String(kind))
	fmt.Fprintf(w, "  status:      %s\n", status)

	// Only print what carries signal; a clean result has no threat metadata.
	d := r.Details
	field(w, "note", note)
	field(w, "severity", d.SeverityLevel)
	field(w, "description", d.Description)
	field(w, "versions", r.AffectedVersions())
	field(w, "warning", r.Warning)
	field(w, "tags", strings.Join(d.Tags, ", "))
	field(w, "first_seen", d.FirstSeen)
	field(w, "url", r.OSMURL)
}

// field prints one aligned "key: value" line, skipping empty values.
func field(w io.Writer, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	fmt.Fprintf(w, "  %-12s %s\n", key+":", termsafe.String(value))
}
