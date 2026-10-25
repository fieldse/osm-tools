package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestSweepTable_CellsSanitised(t *testing.T) {
	var buf bytes.Buffer
	SweepTable(&buf, []SweepRow{
		{Package: "evil\x1b[1A\rok", Version: "1.0.0", Status: "MALICIOUS", Severity: "high\t\tx", AffectedVersions: "all\n"},
	})
	out := buf.String()
	if strings.ContainsAny(out, "\x1b\r") {
		t.Errorf("table contains control characters: %q", out)
	}
	if lines := strings.Count(strings.TrimRight(out, "\n"), "\n"); lines != 1 {
		t.Errorf("want header plus one row, got %d newlines:\n%s", lines, out)
	}
}

func TestSweepTable_Columns(t *testing.T) {
	var buf bytes.Buffer
	SweepTable(&buf, []SweepRow{{Package: "left-pad", Status: "CLEAN"}})
	out := buf.String()
	if !strings.HasPrefix(out, "PACKAGE") || !strings.Contains(out, "AFFECTED") || strings.Contains(out, "FIRST_SEEN") {
		t.Errorf("unexpected header:\n%s", out)
	}
	if !strings.Contains(out, "left-pad  -        CLEAN") {
		t.Errorf("empty version should render as -:\n%s", out)
	}
}
