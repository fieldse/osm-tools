package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/client"
)

func fullRequest() client.SubmitRequest {
	return client.SubmitRequest{
		ReportType:         "package",
		ResourceIdentifier: "evil-utils",
		PackageName:        "evil-utils",
		Registry:           "npm",
		Publisher:          "totally-legit-dev",
		SeverityLevel:      "high",
		VersionInfo:        "3.3.1, 3.3.2",
		FirstSeen:          "2026-07-14",
		ContactEmail:       "you@example.com",
		ThreatDescription:  strings.Repeat("word ", 40),
		PayloadDescription: "postinstall -> node scripts/setup.js\nc2 fallback ip: 203[.]0[.]113[.]42",
		EvidenceReferences: "https://osv.dev/a|https://npmjs.com/b",
		Tags:               []string{"exfil", "postinstall"},
	}
}

func TestSubmitPreviewShowsEveryPopulatedField(t *testing.T) {
	var buf bytes.Buffer
	SubmitPreview(&buf, fullRequest(), 80)
	got := buf.String()

	for _, want := range []string{
		"type:", "resource:", "registry:", "publisher:", "severity:",
		"versions:", "first seen:", "contact:", "tags:",
		"description:", "payload / IOCs:", "evidence:",
		"evil-utils", "totally-legit-dev", "you@example.com",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("preview missing %q\n%s", want, got)
		}
	}

	// last seen is empty in the fixture and must not render an orphan label.
	if strings.Contains(got, "last seen:") {
		t.Errorf("empty field rendered a label:\n%s", got)
	}
}

// PackageName duplicating ResourceIdentifier is the common case; printing it
// twice is noise.
func TestSubmitPreviewSkipsRedundantPackageName(t *testing.T) {
	var buf bytes.Buffer
	SubmitPreview(&buf, fullRequest(), 80)
	if strings.Contains(buf.String(), "package:") {
		t.Errorf("redundant package row rendered:\n%s", buf.String())
	}

	req := fullRequest()
	req.PackageName = "evil-utils-core"
	buf.Reset()
	SubmitPreview(&buf, req, 80)
	if !strings.Contains(buf.String(), "package:") {
		t.Errorf("distinct package name should render:\n%s", buf.String())
	}
}

// The bug this rewrite fixes: wrapped prose used to resume at column zero,
// where it read as another label row.
func TestSubmitPreviewWrapsAndIndentsLongText(t *testing.T) {
	var buf bytes.Buffer
	SubmitPreview(&buf, fullRequest(), 80)

	var sawWrapped bool
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.Contains(line, "word word") {
			continue
		}
		sawWrapped = true
		if !strings.HasPrefix(line, "    ") {
			t.Errorf("wrapped line not indented: %q", line)
		}
		if len([]rune(line)) > 80 {
			t.Errorf("line exceeds width 80 (%d): %q", len([]rune(line)), line)
		}
	}
	if !sawWrapped {
		t.Fatal("description did not render")
	}
}

func TestSubmitPreviewSplitsPipedEvidence(t *testing.T) {
	var buf bytes.Buffer
	SubmitPreview(&buf, fullRequest(), 80)
	got := buf.String()

	if strings.Contains(got, "https://osv.dev/a|https://npmjs.com/b") {
		t.Errorf("evidence still pipe-joined:\n%s", got)
	}
	for _, want := range []string{"- https://osv.dev/a", "- https://npmjs.com/b"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing evidence bullet %q\n%s", want, got)
		}
	}
}

// Multi-line IOC lists must keep their line structure rather than reflowing
// into a paragraph.
func TestSubmitPreviewPreservesPayloadLineBreaks(t *testing.T) {
	var buf bytes.Buffer
	SubmitPreview(&buf, fullRequest(), 80)

	if !strings.Contains(buf.String(), "    postinstall -> node scripts/setup.js\n") {
		t.Errorf("payload lines reflowed:\n%s", buf.String())
	}
}

func TestSubmitPreviewWidthHandling(t *testing.T) {
	// A word longer than the wrap width overflows rather than being broken, so
	// URLs stay copy-pasteable; only wrapped prose is width-checked here.
	for _, width := range []int{0, 10, 80, 500} {
		var buf bytes.Buffer
		SubmitPreview(&buf, fullRequest(), width)
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, "word word") && len([]rune(line)) > previewMaxWidth {
				t.Errorf("width %d produced an over-wide line (%d): %q",
					width, len([]rune(line)), line)
			}
		}
	}
}

func TestSubmitPreviewMinimalReport(t *testing.T) {
	var buf bytes.Buffer
	SubmitPreview(&buf, client.SubmitRequest{
		ReportType:         "domain",
		ResourceIdentifier: "evil.example.com",
		ThreatDescription:  "phishing host",
	}, 80)
	got := buf.String()

	if !strings.Contains(got, "evil.example.com") || !strings.Contains(got, "phishing host") {
		t.Errorf("minimal report lost content:\n%s", got)
	}
	for _, absent := range []string{"payload / IOCs:", "evidence:", "severity:", "downloads:"} {
		if strings.Contains(got, absent) {
			t.Errorf("empty section %q rendered:\n%s", absent, got)
		}
	}
}
