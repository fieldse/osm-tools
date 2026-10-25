package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/verdict"
)

func TestCheckDetail_Malicious(t *testing.T) {
	var buf bytes.Buffer
	CheckDetail(&buf, "evil", "package", client.CheckResult{
		Malicious: true,
		Details: client.Details{
			SeverityLevel: "critical",
			Description:   "credential stealer",
			Tags:          []string{"stealer", "npm"},
			FirstSeen:     "2026-05-01",
		},
	}, verdict.Malicious, "")

	out := buf.String()
	for _, want := range []string{"evil (package)", "MALICIOUS", "critical", "credential stealer", "stealer, npm", "2026-05-01"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
}

func TestCheckDetail_Clean(t *testing.T) {
	var buf bytes.Buffer
	CheckDetail(&buf, "express", "package", client.CheckResult{Malicious: false}, verdict.Clean, "")

	out := buf.String()
	if !strings.Contains(out, "CLEAN") {
		t.Errorf("expected CLEAN, got:\n%s", out)
	}
	// Empty fields shouldn't print stray labels.
	if strings.Contains(out, "severity:") {
		t.Errorf("clean result should omit empty severity:\n%s", out)
	}
}

func TestCheckDetail_Note(t *testing.T) {
	var buf bytes.Buffer
	CheckDetail(&buf, "g:a", "package", client.CheckResult{Malicious: true}, verdict.Review, "matched on artifactId only")

	out := buf.String()
	for _, want := range []string{"REVIEW", "note:        matched on artifactId only"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
}
