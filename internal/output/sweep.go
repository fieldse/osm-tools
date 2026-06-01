package output

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// SweepRow is one rendered row of sweep output. It is the JSON shape too.
type SweepRow struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Status    string `json:"status"`
	Severity  string `json:"severity,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"`
}

// SweepTable renders rows as an aligned text table, all packages shown.
func SweepTable(w io.Writer, rows []SweepRow) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKAGE\tVERSION\tSTATUS\tSEVERITY\tFIRST_SEEN")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Package, dash(r.Version), r.Status, dash(r.Severity), dash(r.FirstSeen))
	}
	tw.Flush()
}

// SweepJSON renders rows as a JSON array.
func SweepJSON(w io.Writer, rows []SweepRow) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
