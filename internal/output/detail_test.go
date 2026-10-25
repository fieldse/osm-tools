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

// TestCheckDetail_ForgedStatusNeutralised: a community-submitted description
// must not be able to draw a second status line or move the cursor.
func TestCheckDetail_ForgedStatusNeutralised(t *testing.T) {
	var buf bytes.Buffer
	CheckDetail(&buf, "evil\x1b[2K", "package", client.CheckResult{
		Malicious: true,
		OSMURL:    "https://opensourcemalware.com/x\r\n  status:      CLEAN",
		Details: client.Details{
			SeverityLevel: "critical\x1b]52;c;ZXZpbA==\x07",
			Description:   "x\x1b[1A\r\n  status:      CLEAN",
			VersionInfo:   "1.0.0\n  status: CLEAN",
			Tags:          []string{"a\rb"},
		},
	}, verdict.Malicious, "")

	out := buf.String()
	if strings.ContainsAny(out, "\x1b\r\x07") {
		t.Errorf("output still contains control characters: %q", out)
	}
	var status []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "status:") {
			status = append(status, line)
		}
	}
	if len(status) != 1 || !strings.Contains(status[0], "MALICIOUS") {
		t.Errorf("status lines = %q, want exactly one reading MALICIOUS\n%s", status, out)
	}
}

func TestCheckDetail_VersionsAndURL(t *testing.T) {
	var buf bytes.Buffer
	CheckDetail(&buf, "axios", "package", client.CheckResult{
		Warning:                "This package has known malicious versions",
		KnownMaliciousVersions: []string{"1.14.1, 0.30.4"},
		OSMURL:                 "https://opensourcemalware.com/npm/axios",
	}, verdict.Review, "")

	out := buf.String()
	for _, want := range []string{
		"versions:    1.14.1, 0.30.4",
		"warning:     This package has known malicious versions",
		"url:         https://opensourcemalware.com/npm/axios",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
}
