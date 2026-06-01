package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/client"
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
	})

	out := buf.String()
	for _, want := range []string{"evil (package)", "MALICIOUS", "critical", "credential stealer", "stealer, npm", "2026-05-01"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
}

func TestCheckDetail_Clean(t *testing.T) {
	var buf bytes.Buffer
	CheckDetail(&buf, "express", "package", client.CheckResult{Malicious: false})

	out := buf.String()
	if !strings.Contains(out, "CLEAN") {
		t.Errorf("expected CLEAN, got:\n%s", out)
	}
	// Empty fields shouldn't print stray labels.
	if strings.Contains(out, "severity:") {
		t.Errorf("clean result should omit empty severity:\n%s", out)
	}
}
