// Package output renders command results to an io.Writer. Keeping formatting
// here (rather than in cmd) lets it be unit-tested with a buffer.
package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/fieldse/osm-tools/internal/client"
)

// CheckDetail renders a single check result as a human-readable block. label is
// the resource that was checked (name, domain, IP, or image reference) and
// kind is the resolved type.
func CheckDetail(w io.Writer, label, kind string, r client.CheckResult) {
	status := "CLEAN"
	if r.Malicious {
		status = "MALICIOUS"
	}

	fmt.Fprintf(w, "%s (%s)\n", label, kind)
	fmt.Fprintf(w, "  status:      %s\n", status)

	// Threat metadata lives in Details; for clean results it's empty, so only
	// print what carries signal.
	d := r.Details
	if d.SeverityLevel != "" {
		fmt.Fprintf(w, "  severity:    %s\n", d.SeverityLevel)
	}
	if d.Description != "" {
		fmt.Fprintf(w, "  description: %s\n", d.Description)
	}
	if len(d.Tags) > 0 {
		fmt.Fprintf(w, "  tags:        %s\n", strings.Join(d.Tags, ", "))
	}
	if d.FirstSeen != "" {
		fmt.Fprintf(w, "  first_seen:  %s\n", d.FirstSeen)
	}
}
