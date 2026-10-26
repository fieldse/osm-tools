package output

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/fieldse/osm-tools/internal/termsafe"
)

// SweepRow is one rendered row of sweep output. It is the JSON shape too.
type SweepRow struct {
	Package          string `json:"package"`
	Version          string `json:"version"`
	Status           string `json:"status"`
	Severity         string `json:"severity,omitempty"`
	AffectedVersions string `json:"affected_versions,omitempty"`
	OSMURL           string `json:"osm_url,omitempty"`
}

// SweepTable renders rows as an aligned text table, all packages shown.
// Cells come from manifests and the API, so each passes through termsafe.
func SweepTable(w io.Writer, rows []SweepRow) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKAGE\tVERSION\tSTATUS\tSEVERITY\tAFFECTED")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			cell(r.Package), cell(r.Version), cell(r.Status), cell(r.Severity), cell(r.AffectedVersions))
	}
	tw.Flush()
}

// SweepJSON renders rows as a JSON array.
func SweepJSON(w io.Writer, rows []SweepRow) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // this is terminal output, not an HTML <script> body
	return enc.Encode(rows)
}

// cell sanitises s for the table and shows "-" for an empty value.
func cell(s string) string {
	if s == "" {
		return "-"
	}
	return termsafe.String(s)
}
