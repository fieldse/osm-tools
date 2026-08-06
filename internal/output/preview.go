package output

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/fieldse/osm-tools/internal/client"
)

// Preview layout constants. Long-form text is wrapped to fit the terminal but
// capped, since full-width prose is harder to scan than a column.
const (
	previewMinWidth = 40
	previewMaxWidth = 100
	previewIndent   = "  "
	previewLabelPad = 12 // widest label ("description:") + a space
)

// SubmitPreview renders the report a submit is about to send. It is the last
// thing a user sees before confirming, so every field going on the wire is
// shown: scalars in an aligned column, the three long-form fields as wrapped
// blocks, and evidence one reference per line. width is the terminal width;
// pass 0 when unknown.
func SubmitPreview(w io.Writer, req client.SubmitRequest, width int) {
	width = clampWidth(width)

	fmt.Fprintf(w, "\n%s\n", rule("report preview", width))

	// Scalars first: everything that fits on one line, aligned so the values
	// form a scannable column. Empty fields carry no signal and are skipped.
	pkg := req.PackageName
	if pkg == req.ResourceIdentifier {
		pkg = "" // already shown as the resource; repeating it is noise
	}
	for _, f := range []struct{ label, value string }{
		{"type", req.ReportType},
		{"resource", req.ResourceIdentifier},
		{"package", pkg},
		{"registry", req.Registry},
		{"publisher", req.Publisher},
		{"severity", req.SeverityLevel},
		{"versions", req.VersionInfo},
		{"first seen", req.FirstSeen},
		{"last seen", req.LastSeen},
		{"contact", req.ContactEmail},
		{"osv", req.OSVAdvisoryURL},
		{"tags", strings.Join(req.Tags, ", ")},
		{"contributors", strings.Join(req.Contributors, ", ")},
	} {
		if f.value != "" {
			fmt.Fprintf(w, "%s%-*s %s\n", previewIndent, previewLabelPad, f.label+":", f.value)
		}
	}
	if req.DownloadCount > 0 {
		fmt.Fprintf(w, "%s%-*s %d\n", previewIndent, previewLabelPad, "downloads:", req.DownloadCount)
	}

	// Long-form fields as their own blocks. Inline they wrapped back to column
	// zero and ran together with the labels above.
	writeBlock(w, "description", req.ThreatDescription, width)
	writeBlock(w, "payload / IOCs", req.PayloadDescription, width)

	// Evidence travels as a pipe-delimited string; split it back so each
	// reference is checkable on its own line.
	if req.EvidenceReferences != "" {
		fmt.Fprintf(w, "\n%s%s:\n", previewIndent, "evidence")
		for _, ref := range strings.Split(req.EvidenceReferences, "|") {
			if ref = strings.TrimSpace(ref); ref != "" {
				fmt.Fprintf(w, "%s%s- %s\n", previewIndent, previewIndent, ref)
			}
		}
	}

	fmt.Fprintf(w, "%s\n", rule("", width))
}

// writeBlock renders a labelled block of free text, wrapped and indented under
// its heading. Existing line breaks are preserved so multi-line IOC lists keep
// their shape.
func writeBlock(w io.Writer, label, body string, width int) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}

	indent := previewIndent + previewIndent
	fmt.Fprintf(w, "\n%s%s:\n", previewIndent, label)
	for _, line := range wrapText(body, width-utf8.RuneCountInString(indent)) {
		if line == "" {
			fmt.Fprintln(w)
			continue
		}
		fmt.Fprintf(w, "%s%s\n", indent, line)
	}
}

// wrapText word-wraps s to width columns, preserving its existing line breaks.
// A single word longer than width (typically a URL) is left to overflow rather
// than hard-broken, so it stays selectable and copy-pasteable.
func wrapText(s string, width int) []string {
	if width < 1 {
		width = 1
	}

	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}

		line := words[0]
		for _, word := range words[1:] {
			if utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width {
				out = append(out, line)
				line = word
				continue
			}
			line += " " + word
		}
		out = append(out, line)
	}
	return out
}

// rule draws a full-width separator, with title inset when given.
func rule(title string, width int) string {
	if title == "" {
		return strings.Repeat("─", width)
	}
	prefix := "── " + title + " "
	if pad := width - utf8.RuneCountInString(prefix); pad > 0 {
		return prefix + strings.Repeat("─", pad)
	}
	return prefix
}

// clampWidth keeps the preview readable when the terminal is unknown (0),
// very narrow, or very wide.
func clampWidth(width int) int {
	switch {
	case width <= 0:
		return 80
	case width < previewMinWidth:
		return previewMinWidth
	case width > previewMaxWidth:
		return previewMaxWidth
	}
	return width
}
