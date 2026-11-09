package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/exitcode"
	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/fieldse/osm-tools/internal/report"
)

// Tests for `osm submit` command wiring. Drives the TTY seam via opts.isTerminal
// and stdin via cmd.SetIn, per IMPLEMENTATION_CONTRACT.md §6–§11. Reuses
// testDeps(srv) from check_test.go. Case IDs map to docs/submit-report-spec.md.

// --- test helpers ---

// recorder captures what the fake OSM server saw. It distinguishes submit POSTs
// (POST /submit-threat-report) from best-effort dedupe GETs so tests can assert
// that the no-network paths never fire a submit.
type recorder struct {
	mu           sync.Mutex
	posts        int
	gets         int
	lastBody     client.SubmitRequest
	lastRaw      []byte
	submitStatus int    // 0 → 201
	submitResp   string // "" → default success body
}

func (r *recorder) postCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.posts
}

func (r *recorder) body() client.SubmitRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastBody
}

// newRecordingServer returns an httptest server that answers submit POSTs from
// the recorder's config and any other request (dedupe GET) with a benign
// not-malicious body.
func newRecordingServer(rec *recorder) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "submit-threat-report") {
			rec.posts++
			body, _ := io.ReadAll(r.Body)
			rec.lastRaw = body
			_ = json.Unmarshal(body, &rec.lastBody)
			status := rec.submitStatus
			if status == 0 {
				status = http.StatusCreated
			}
			w.WriteHeader(status)
			if rec.submitResp != "" {
				w.Write([]byte(rec.submitResp))
			} else {
				w.Write([]byte(`{"threat_id":"THREAT-123","status":"pending"}`))
			}
			return
		}
		// best-effort dedupe lookup
		rec.gets++
		w.Write([]byte(`{"malicious":false}`))
	}))
}

// writeTempFile writes content to a temp file and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return p
}

// validTemplate is a minimal report with all required fields present plus a live
// IOC in the payload and an OSV url in evidence (for defang assertions).
const validTemplate = `# test threat

- Type: package
- Resource: evil-pkg
- Registry: npm

## Description
does bad things

## Payload / IOCs
run http://evil.com now

## Evidence
- https://osv.dev/GHSA-1
`

// --- Sending & safety (T1, T3, T4, T5) ---

// TestSubmit_HappyPath (T1) feeds a valid template file with confirmation and
// asserts exactly one POST fires and the returned threat_id is printed.
func TestSubmit_HappyPath(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	cmd := newSubmitCmd(testDeps(srv))
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader("y\n"))

	opts := &submitOptions{file: path, isTerminal: func() bool { return true }}
	if err := runSubmit(cmd, testDeps(srv), opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rec.postCount(); got != 1 {
		t.Fatalf("submit POSTs = %d, want 1", got)
	}
	if !strings.Contains(out.String(), "THREAT-123") {
		t.Errorf("stdout missing threat_id:\n%s", out.String())
	}
}

// TestSubmit_DeclineSendsNothing (T3) declines the confirm prompt and asserts
// zero submit requests were made.
func TestSubmit_DeclineSendsNothing(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader("n\n"))

	opts := &submitOptions{file: path, isTerminal: func() bool { return true }}
	if err := runSubmit(cmd, deps, opts); err != nil {
		t.Fatalf("decline should be a clean abort, got: %v", err)
	}
	if got := rec.postCount(); got != 0 {
		t.Errorf("submit POSTs = %d, want 0 after decline", got)
	}
}

// TestSubmit_NonTTYWithoutYesRefuses (T4) sets isTerminal=false with no --yes
// and asserts a UsageError and no request.
func TestSubmit_NonTTYWithoutYesRefuses(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	opts := &submitOptions{file: path, isTerminal: func() bool { return false }}
	err := runSubmit(cmd, deps, opts)
	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want UsageError, got %v", err)
	}
	if got := rec.postCount(); got != 0 {
		t.Errorf("submit POSTs = %d, want 0", got)
	}
}

// TestSubmit_YesAutoConfirms (T5) passes --yes and asserts the report submits
// with no prompt read (isTerminal false, empty stdin).
func TestSubmit_YesAutoConfirms(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader("")) // must not be read

	opts := &submitOptions{file: path, yes: true, isTerminal: func() bool { return false }}
	if err := runSubmit(cmd, deps, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rec.postCount(); got != 1 {
		t.Errorf("submit POSTs = %d, want 1", got)
	}
}

// --- Modes & mutual exclusivity (T6, T7, T10) ---

// TestSubmit_ThreeModesAssembleSame (T6) builds the same report via template,
// --from-json, and interactive transcript and asserts identical SubmitRequests.
func TestSubmit_ThreeModesAssembleSame(t *testing.T) {
	deps := testDeps(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))

	tmpl := `# evil-pkg backdoor

- Type: package
- Resource: evil-pkg
- Package name: evil-pkg
- Registry: npm
- Publisher: baduser
- Contact: abuse@example.com
- Affected versions: 1.0.0
- Severity: high
- First seen: 2026-01-01T00:00:00Z
- Last seen: 2026-02-01T00:00:00Z
- OSV: https://osv.dev/GHSA-xxxx
- Tags: malware, backdoor

## Description
It is bad

## Payload / IOCs
curl http://evil.com

## Evidence
- https://osv.dev/GHSA-xxxx
- https://example.com/report
`

	jsonDoc := `{
  "report_type": "package",
  "resource_identifier": "evil-pkg",
  "threat_description": "It is bad",
  "package_name": "evil-pkg",
  "registry": "npm",
  "publisher": "baduser",
  "contact_email": "abuse@example.com",
  "payload_description": "curl http://evil.com",
  "severity_level": "high",
  "evidence_references": ["https://osv.dev/GHSA-xxxx", "https://example.com/report"],
  "version_info": "1.0.0",
  "first_seen": "2026-01-01T00:00:00Z",
  "last_seen": "2026-02-01T00:00:00Z",
  "osv_advisory_url": "https://osv.dev/GHSA-xxxx",
  "tags": ["malware", "backdoor"]
}`

	// interactive transcript in the fixed §10 field order; "." terminates the
	// multi-line description/payload/evidence blocks.
	transcript := strings.Join([]string{
		"package",                   // report_type
		"evil-pkg",                  // resource_identifier
		"evil-pkg",                  // package_name
		"npm",                       // registry
		"baduser",                   // publisher
		"abuse@example.com",         // contact_email
		"high",                      // severity_level
		"1.0.0",                     // version_info
		"2026-01-01T00:00:00Z",      // first_seen
		"2026-02-01T00:00:00Z",      // last_seen
		"https://osv.dev/GHSA-xxxx", // osv_advisory_url
		"malware, backdoor",         // tags
		"It is bad", ".",            // description (multi-line)
		"curl http://evil.com", ".", // payload_description (multi-line)
		"https://osv.dev/GHSA-xxxx",  // evidence 1
		"https://example.com/report", // evidence 2
		".",                          // end evidence
	}, "\n") + "\n"

	tmplPath := writeTempFile(t, "r.md", tmpl)
	jsonPath := writeTempFile(t, "r.json", jsonDoc)

	collect := func(opts *submitOptions, stdin string) client.SubmitRequest {
		t.Helper()
		cmd := newSubmitCmd(deps)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetIn(strings.NewReader(stdin))
		r, err := collectReport(cmd, deps, opts)
		if err != nil {
			t.Fatalf("collectReport: %v", err)
		}
		return toSubmitRequest(r)
	}

	fromTmpl := collect(&submitOptions{file: tmplPath}, "")
	fromJSON := collect(&submitOptions{fromJSON: jsonPath}, "")
	fromInteractive := collect(&submitOptions{interactive: true, isTerminal: func() bool { return true }}, transcript)

	if !reflect.DeepEqual(fromTmpl, fromJSON) {
		t.Errorf("template vs json differ:\n template=%+v\n json=%+v", fromTmpl, fromJSON)
	}
	if !reflect.DeepEqual(fromTmpl, fromInteractive) {
		t.Errorf("template vs interactive differ:\n template=%+v\n interactive=%+v", fromTmpl, fromInteractive)
	}
}

// --- Ctrl-C at a prompt (interrupt handling) ---

// blockingReader stands in for a TTY waiting on a user who never types: Read
// parks until the test releases it. A plain empty reader would hit EOF and let
// the prompt fall through, which would pass these tests for the wrong reason.
type blockingReader struct{ release chan struct{} }

func (b blockingReader) Read(p []byte) (int, error) {
	<-b.release
	return 0, io.EOF
}

// TestSubmit_InterruptAtConfirmAborts asserts Ctrl-C at the confirm prompt ends
// the run instead of hanging. main installs a signal handler that only cancels
// the context, so a prompt blocked on a raw stdin read would ignore the
// interrupt and wait forever.
func TestSubmit_InterruptAtConfirmAborts(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	release := make(chan struct{})
	defer close(release)
	cmd.SetIn(blockingReader{release: release})

	ctx, cancel := context.WithCancel(context.Background())
	cmd.SetContext(ctx)
	cancel() // Ctrl-C lands while the prompt waits

	done := make(chan error, 1)
	go func() {
		done <- runSubmit(cmd, deps, &submitOptions{
			file: path, isTerminal: func() bool { return true },
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Ctrl-C at the confirm prompt should abort cleanly, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runSubmit hung after Ctrl-C — the prompt is ignoring context cancellation")
	}

	if !strings.Contains(errBuf.String(), "aborted") {
		t.Errorf("interrupt should report an abort, stderr was:\n%s", errBuf.String())
	}
	if rec.postCount() != 0 {
		t.Errorf("submit POSTs = %d, want 0 after an interrupt", rec.postCount())
	}
}

// TestSubmit_InterruptInWizardAborts asserts Ctrl-C mid-wizard ends the run
// rather than marching through the remaining prompts.
func TestSubmit_InterruptInWizardAborts(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	release := make(chan struct{})
	defer close(release)
	cmd.SetIn(blockingReader{release: release})

	ctx, cancel := context.WithCancel(context.Background())
	cmd.SetContext(ctx)
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- runSubmit(cmd, deps, &submitOptions{
			interactive: true, isTerminal: func() bool { return true },
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Ctrl-C in the wizard should abort cleanly, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wizard hung after Ctrl-C — a prompt is ignoring context cancellation")
	}

	if rec.postCount() != 0 {
		t.Errorf("submit POSTs = %d, want 0 after an interrupt", rec.postCount())
	}
}

// TestSubmit_SharedStdinReader asserts the wizard and the confirm prompt read
// through one reader. Two readers would race for the next line, letting an
// abandoned wizard goroutine swallow the confirm answer — the report would then
// silently not submit despite a "y".
func TestSubmit_SharedStdinReader(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	// A full wizard transcript with the confirm answer appended.
	transcript := interactiveTranscript(t,
		[]string{
			"package", "@acme/utils", "", "",
			"", "", "", "", "", "", "", "",
		},
		"steals npmrc", "") + "y\n"

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(transcript))

	opts := &submitOptions{interactive: true, isTerminal: func() bool { return true }}
	if err := runSubmit(cmd, deps, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.postCount() != 1 {
		t.Errorf("submit POSTs = %d, want 1 — the confirm 'y' after the wizard was not read", rec.postCount())
	}
}

// --- Interactive affordances (defaults, enum re-prompt, hints) ---

// interactiveTranscript builds a wizard transcript from the given answers,
// appending the terminators for the three trailing blocks so cases only have to
// state the single-line answers they care about.
func interactiveTranscript(t *testing.T, singleLine []string, desc, payload string, evidence ...string) string {
	t.Helper()
	lines := append([]string{}, singleLine...)
	lines = append(lines, desc, ".", payload, ".")
	lines = append(lines, evidence...)
	lines = append(lines, ".")
	return strings.Join(lines, "\n") + "\n"
}

// runInteractive drives collectInteractive over a transcript and returns the
// assembled report plus everything the wizard printed to stderr.
func runInteractive(t *testing.T, transcript string) (report.Report, string) {
	t.Helper()
	deps := testDeps(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	cmd := newSubmitCmd(deps)
	var errBuf bytes.Buffer
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(transcript))

	r, err := collectInteractive(cmd, deps, &submitOptions{
		interactive: true,
		isTerminal:  func() bool { return true },
	})
	if err != nil {
		t.Fatalf("collectInteractive: %v", err)
	}
	return r, errBuf.String()
}

// TestSubmit_InteractiveDefaults asserts a bare Enter on report_type takes the
// package default rather than submitting an empty field.
func TestSubmit_InteractiveDefaults(t *testing.T) {
	// report_type left blank; everything else answered or skipped.
	transcript := interactiveTranscript(t,
		[]string{
			"",                             // report_type   -> default package
			"@acme/utils",                  // resource_identifier
			"",                             // package_name
			"",                             // registry
			"", "", "", "", "", "", "", "", // publisher..tags
		},
		"steals npmrc", "http://evil.com")

	r, _ := runInteractive(t, transcript)

	if r.Type != report.TypePackage {
		t.Errorf("report_type = %q, want the %q default on blank input", r.Type, report.TypePackage)
	}
}

// TestSubmit_InteractiveRejectsBadTypeInline asserts an invalid report_type is
// re-prompted on the spot. Without this the wizard accepts the typo and only
// fails at Validate — after every other field has been typed.
func TestSubmit_InteractiveRejectsBadTypeInline(t *testing.T) {
	transcript := interactiveTranscript(t,
		[]string{
			"pakcage",     // typo -> re-prompt
			"package",     // corrected
			"@acme/utils", // resource_identifier
			"", "",        // package_name, registry
			"", "", "", "", "", "", "", "", // publisher..tags
		},
		"steals npmrc", "")

	r, transcriptOut := runInteractive(t, transcript)

	if r.Type != report.TypePackage {
		t.Errorf("report_type = %q, want %q after correction", r.Type, report.TypePackage)
	}
	if !strings.Contains(transcriptOut, "not a valid report_type") {
		t.Errorf("wizard did not flag the bad report_type inline:\n%s", transcriptOut)
	}
}

// TestSubmit_InteractivePromptsCarryHints asserts each prompt states whether the
// field is required and offers a vocabulary or example — the wizard's whole
// point is that you can answer it without the API docs open.
func TestSubmit_InteractivePromptsCarryHints(t *testing.T) {
	transcript := interactiveTranscript(t,
		[]string{
			"package", "@acme/utils", "", "",
			"", "", "", "", "", "", "", "",
		},
		"steals npmrc", "")

	_, out := runInteractive(t, transcript)

	for _, want := range []string{
		"report_type",
		"(required)",
		"(optional)",
		"package|container|repository|url|domain|ip|wallet", // type vocabulary
		"critical|high|medium|low",                          // severity vocabulary
		"npm|pypi",                                          // registry vocabulary
		"(default: package) > ",                             // default shown before the marker
		"YYYY-MM-DD",                                        // date format hint
		"Example:",                                          // block examples
		"publisher (optional)\n  the attacker's account that published it (not you)\n" +
			"  e.g. npm/PyPI username, GitHub user or org: baduser\n> ", // publisher means the attacker
		"tags (optional)\n  comma-separated, lowercase kebab-case, e.g. contagious-interview, infostealer, postinstall\n" +
			"  tag list: https://docs.opensourcemalware.com/tags.md\n> ", // tags follow OSM's convention
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt transcript missing %q:\n%s", want, out)
		}
	}
}

// TestResourceHint asserts each report type gets the resource_identifier format
// from the OSM submit-threat docs.
func TestResourceHint(t *testing.T) {
	for _, tc := range []struct {
		reportType string
		want       []string
	}{
		{report.TypePackage, []string{"npm:    @scope/package-name", "pypi:   requests-toolkit", "skills: https://www.clawhub.ai/user/skill-name"}},
		{report.TypeRepository, []string{"no https://", "github.com/owner/repo"}},
		{report.TypeURL, []string{"https://example.com/payload"}},
		{report.TypeDomain, []string{"bare domain", "evil-c2-server.com"}},
		{report.TypeIP, []string{"192.0.2.1"}},
		{report.TypeWallet, []string{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}},
		{report.TypeContainer, []string{"docker.io/owner/image:latest"}},
		{report.TypeDocker, []string{"docker.io/owner/image:latest"}},
		{"bogus", []string{"what you're reporting"}},
	} {
		t.Run(tc.reportType, func(t *testing.T) {
			got := resourceHint(tc.reportType)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("resourceHint(%q) = %q, missing %q", tc.reportType, got, w)
				}
			}
			if tc.reportType == report.TypeRepository && strings.Contains(got, "https://github") {
				t.Errorf("repository hint shows a protocol: %q", got)
			}
		})
	}
}

// TestSubmit_InteractiveResourceHintFollowsType asserts the resource_identifier
// prompt shows the hint for the report_type just answered.
func TestSubmit_InteractiveResourceHintFollowsType(t *testing.T) {
	for _, tc := range []struct {
		reportType, resource string
		want                 []string
	}{
		{"repository", "github.com/evil/repo", []string{
			"resource_identifier (required)\n  host and path, no https://, e.g. github.com/owner/repo\n> ",
		}},
		{"package", "@acme/utils", []string{
			"resource_identifier (required)\n  name as it appears in the registry, e.g.\n",
			"    npm:    @scope/package-name  or  package-name\n",
			"    pypi:   requests-toolkit\n",
		}},
	} {
		t.Run(tc.reportType, func(t *testing.T) {
			transcript := interactiveTranscript(t,
				[]string{
					tc.reportType, tc.resource, "", "",
					"", "", "", "", "", "", "", "",
				},
				"steals npmrc", "")

			_, out := runInteractive(t, transcript)

			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("transcript missing %q:\n%s", w, out)
				}
			}
		})
	}
}

// TestSubmit_InteractiveDatesAndRegistryHaveNoDefault asserts blank first_seen,
// last_seen and registry stay empty rather than taking a guessed value.
func TestSubmit_InteractiveDatesAndRegistryHaveNoDefault(t *testing.T) {
	transcript := interactiveTranscript(t,
		[]string{
			"package", "@acme/utils", "", "",
			"", "", "", "", // publisher..version_info
			"",     // first_seen
			"",     // last_seen
			"", "", // osv_advisory_url, tags
		},
		"steals npmrc", "")

	deps := testDeps(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	cmd := newSubmitCmd(deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader(transcript))

	r, err := collectInteractive(cmd, deps, &submitOptions{
		interactive: true,
		isTerminal:  func() bool { return true },
	})
	if err != nil {
		t.Fatalf("collectInteractive: %v", err)
	}
	if r.FirstSeen != "" {
		t.Errorf("first_seen = %q, want empty (no default)", r.FirstSeen)
	}
	if r.Registry != "" {
		t.Errorf("registry = %q, want empty (no default)", r.Registry)
	}
	if r.LastSeen != "" {
		t.Errorf("last_seen = %q, want empty (no default)", r.LastSeen)
	}
}

// TestSubmit_InteractiveStripsEvidenceBullets asserts a pasted markdown bullet
// does not become part of the evidence URL — the template writes evidence as a
// "- <url>" list, so people reach for the same shape at the prompt.
func TestSubmit_InteractiveStripsEvidenceBullets(t *testing.T) {
	transcript := interactiveTranscript(t,
		[]string{
			"package", "@acme/utils", "", "",
			"", "", "", "", "", "", "", "",
		},
		"steals npmrc", "",
		"- https://osv.dev/GHSA-1",
		"https://example.com/report",
	)

	r, _ := runInteractive(t, transcript)

	want := []string{"https://osv.dev/GHSA-1", "https://example.com/report"}
	if !reflect.DeepEqual(r.EvidenceRefs, want) {
		t.Errorf("EvidenceRefs = %q, want %q (leading bullet must be stripped)", r.EvidenceRefs, want)
	}
}

// TestSubmit_ConflictingModesError (T7) asserts every combination of two or
// more input modes is a usage error (exit 2) that names each conflicting input
// and sends nothing.
func TestSubmit_ConflictingModesError(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"file+json", []string{"x.md", "--from-json", "y.json"}, []string{`REPORT.md "x.md"`, `--from-json "y.json"`}},
		{"file+json-stdin", []string{"x.md", "--from-json", "-"}, []string{`REPORT.md "x.md"`, `--from-json "-"`}},
		{"file+interactive", []string{"x.md", "-i"}, []string{`REPORT.md "x.md"`, "-i"}},
		{"interactive+json", []string{"-i", "--from-json", "y.json"}, []string{"-i", `--from-json "y.json"`}},
		{"all three", []string{"x.md", "-i", "--from-json", "-"}, []string{`REPORT.md "x.md"`, `--from-json "-"`, "-i"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			srv := newRecordingServer(rec)
			defer srv.Close()

			cmd := newSubmitCmd(testDeps(srv))
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetIn(strings.NewReader(""))
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			var usage *osmerr.UsageError
			if !errors.As(err, &usage) {
				t.Fatalf("want UsageError, got %v", err)
			}
			if code := exitcode.FromError(err); code != exitcode.Usage {
				t.Errorf("exit code = %d, want %d", code, exitcode.Usage)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not name %q", err.Error(), w)
				}
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if rec.posts != 0 || rec.gets != 0 {
				t.Errorf("requests = %d POST, %d GET; want zero network", rec.posts, rec.gets)
			}
		})
	}
}

// TestSubmit_EachSingleModeWorks asserts each input mode on its own assembles
// the report, using --emit-json so nothing is sent.
func TestSubmit_EachSingleModeWorks(t *testing.T) {
	jsonDoc := `{` + jsonReportBase + `}`
	transcript := interactiveTranscript(t,
		[]string{
			"package", "evil-pkg", "", "",
			"", "", "", "", "", "", "", "",
		},
		"bad", "")

	cases := []struct {
		name  string
		opts  func(t *testing.T) *submitOptions
		stdin string
	}{
		{"REPORT.md", func(t *testing.T) *submitOptions {
			return &submitOptions{file: writeTempFile(t, "report.md", validTemplate)}
		}, ""},
		{"--from-json FILE.json", func(t *testing.T) *submitOptions {
			return &submitOptions{fromJSON: writeTempFile(t, "report.json", jsonDoc)}
		}, ""},
		{"--from-json -", func(t *testing.T) *submitOptions {
			return &submitOptions{fromJSON: "-"}
		}, jsonDoc},
		{"-i", func(t *testing.T) *submitOptions {
			return &submitOptions{interactive: true, isTerminal: func() bool { return true }}
		}, transcript},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			srv := newRecordingServer(rec)
			defer srv.Close()

			deps := testDeps(srv)
			cmd := newSubmitCmd(deps)
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetIn(strings.NewReader(tc.stdin))

			opts := tc.opts(t)
			opts.emitJSON = true
			if err := runSubmit(cmd, deps, opts); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var req client.SubmitRequest
			if err := json.Unmarshal(out.Bytes(), &req); err != nil {
				t.Fatalf("emit-json output not valid JSON: %v\n%s", err, out.String())
			}
			if req.ResourceIdentifier != "evil-pkg" {
				t.Errorf("resource_identifier = %q, want evil-pkg", req.ResourceIdentifier)
			}
			if rec.postCount() != 0 {
				t.Errorf("submit POSTs = %d, want 0", rec.postCount())
			}
		})
	}
}

// TestSubmit_HelpNamesInputModes asserts `osm submit --help` names the input
// placeholders and lists the three input modes.
func TestSubmit_HelpNamesInputModes(t *testing.T) {
	deps := testDeps(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	cmd := newSubmitCmd(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--help: %v", err)
	}
	help := out.String()

	for _, want := range []string{
		"submit [REPORT.md] [flags]",
		"--from-json FILE.json",
		"Input modes (give exactly one):",
		"--template",
		"--from-json -",
		"stdin",
		"examples/threat-report.json",
		"-i, --interactive       a guided wizard",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help missing %q:\n%s", want, help)
		}
	}
	for _, stale := range []string{"[FILE]", "--from-json string"} {
		if strings.Contains(help, stale) {
			t.Errorf("help still shows %q:\n%s", stale, help)
		}
	}
}

// TestSubmit_BareInvocationUsage (T10) asserts bare `osm submit` returns a
// UsageError and sends nothing.
func TestSubmit_BareInvocationUsage(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	opts := &submitOptions{isTerminal: func() bool { return true }}
	err := runSubmit(cmd, deps, opts)
	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want UsageError, got %v", err)
	}
	if got := rec.postCount(); got != 0 {
		t.Errorf("submit POSTs = %d, want 0", got)
	}
}

// --- No-network escape hatches (T8, T9) ---

// TestSubmit_TemplatePrintsAndExits (T8) asserts --template prints the blank
// form to stdout and makes no request.
func TestSubmit_TemplatePrintsAndExits(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	opts := &submitOptions{template: true}
	if err := runSubmit(cmd, deps, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "Type:") || !strings.Contains(got, "## Description") {
		t.Errorf("template output missing expected fields:\n%s", got)
	}
	if rec.postCount() != 0 {
		t.Errorf("submit POSTs = %d, want 0", rec.postCount())
	}
}

// TestSubmit_DryRunNoNetwork (T9) asserts --dry-run makes zero requests.
func TestSubmit_DryRunNoNetwork(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	opts := &submitOptions{file: path, dryRun: true}
	if err := runSubmit(cmd, deps, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.postCount() != 0 {
		t.Errorf("submit POSTs = %d, want 0 for dry-run", rec.postCount())
	}
}

// TestSubmit_EmitJSONNoNetwork (T9) asserts --emit-json prints the assembled
// report as JSON to stdout and makes zero requests.
func TestSubmit_EmitJSONNoNetwork(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	opts := &submitOptions{file: path, emitJSON: true}
	if err := runSubmit(cmd, deps, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.postCount() != 0 {
		t.Errorf("submit POSTs = %d, want 0 for emit-json", rec.postCount())
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("emit-json output not valid JSON: %v\n%s", err, out.String())
	}
	if _, ok := m["report_type"]; !ok {
		t.Errorf("emit-json missing report_type: %v", m)
	}
	if _, ok := m["resource_identifier"]; !ok {
		t.Errorf("emit-json missing resource_identifier: %v", m)
	}
}

// --- Validation surfacing (T11, T12) ---

// TestSubmit_MissingRequiredBlocks (T11) feeds a report missing threat_description
// and asserts a UsageError with no request.
func TestSubmit_MissingRequiredBlocks(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	// required Type/Resource present, Description empty
	noDesc := `# x

- Type: package
- Resource: evil-pkg
- Registry: npm

## Description

## Payload / IOCs

## Evidence
`
	path := writeTempFile(t, "report.md", noDesc)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	opts := &submitOptions{file: path, yes: true, isTerminal: func() bool { return false }}
	err := runSubmit(cmd, deps, opts)
	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want UsageError, got %v", err)
	}
	if rec.postCount() != 0 {
		t.Errorf("submit POSTs = %d, want 0", rec.postCount())
	}
}

// TestSubmit_OptionalGapWarnsAndProceeds (T12) feeds a report with only required
// fields and asserts it still submits.
func TestSubmit_OptionalGapWarnsAndProceeds(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	minimal := `# x

- Type: package
- Resource: evil-pkg

## Description
bad package
`
	path := writeTempFile(t, "report.md", minimal)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	opts := &submitOptions{file: path, yes: true, isTerminal: func() bool { return false }}
	if err := runSubmit(cmd, deps, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.postCount() != 1 {
		t.Errorf("submit POSTs = %d, want 1 (optional gaps must not block)", rec.postCount())
	}
}

// --- Defang at the boundary (T14, T16) ---

// TestSubmit_DefangsPayloadByDefault (T14) asserts a live IOC in the payload is
// defanged on the wire, and evidence/OSV URLs are not.
func TestSubmit_DefangsPayloadByDefault(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	opts := &submitOptions{file: path, yes: true, isTerminal: func() bool { return false }}
	if err := runSubmit(cmd, deps, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.postCount() != 1 {
		t.Fatalf("submit POSTs = %d, want 1", rec.postCount())
	}
	body := rec.body()
	if !strings.Contains(body.PayloadDescription, "hxxp") || !strings.Contains(body.PayloadDescription, "evil[.]com") {
		t.Errorf("payload not defanged on the wire: %q", body.PayloadDescription)
	}
	// evidence must be sent verbatim (never defanged)
	if !strings.Contains(body.EvidenceReferences, "https://osv.dev/GHSA-1") {
		t.Errorf("evidence should not be defanged: %q", body.EvidenceReferences)
	}
}

// TestSubmit_NoDefangSendsVerbatim (T16) asserts --no-defang leaves the payload
// IOCs intact on the wire.
func TestSubmit_NoDefangSendsVerbatim(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	opts := &submitOptions{file: path, yes: true, noDefang: true, isTerminal: func() bool { return false }}
	if err := runSubmit(cmd, deps, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := rec.body()
	if !strings.Contains(body.PayloadDescription, "http://evil.com") {
		t.Errorf("--no-defang should send verbatim IOC, got: %q", body.PayloadDescription)
	}
}

// --- Mapping & error surfacing (T2, T17, T18, T19) ---

// TestToSubmitRequest_Mapping (T2) asserts toSubmitRequest joins evidence with
// "|" and maps every field onto the correct wire name.
func TestToSubmitRequest_Mapping(t *testing.T) {
	r := report.Report{
		Type:               report.TypePackage,
		ResourceID:         "evil-pkg",
		Description:        "does bad things",
		PackageName:        "evil-pkg",
		Registry:           "npm",
		Publisher:          "baduser",
		ContactEmail:       "abuse@example.com",
		PayloadDescription: "curl http://evil.com",
		SeverityLevel:      "high",
		EvidenceRefs:       []string{"a", "b"},
		VersionInfo:        "1.0.0",
		FirstSeen:          "2026-01-01T00:00:00Z",
		LastSeen:           "2026-02-01T00:00:00Z",
		OSVAdvisoryURL:     "https://osv.dev/GHSA-1",
		Tags:               []string{"malware", "backdoor"},
		Contributors:       []string{"bob"},
		DownloadCount:      42,
	}
	got := toSubmitRequest(r)

	if got.EvidenceReferences != "a|b" {
		t.Errorf("EvidenceReferences = %q, want %q", got.EvidenceReferences, "a|b")
	}
	want := client.SubmitRequest{
		ReportType:         "package",
		ResourceIdentifier: "evil-pkg",
		ThreatDescription:  "does bad things",
		PackageName:        "evil-pkg",
		Registry:           "npm",
		Publisher:          "baduser",
		ContactEmail:       "abuse@example.com",
		PayloadDescription: "curl http://evil.com",
		SeverityLevel:      "high",
		EvidenceReferences: "a|b",
		VersionInfo:        "1.0.0",
		FirstSeen:          "2026-01-01T00:00:00Z",
		LastSeen:           "2026-02-01T00:00:00Z",
		OSVAdvisoryURL:     "https://osv.dev/GHSA-1",
		Tags:               []string{"malware", "backdoor"},
		Contributors:       []string{"bob"},
		DownloadCount:      42,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("toSubmitRequest mismatch:\n got=%+v\n want=%+v", got, want)
	}
}

// TestSubmit_NoToken (T18) asserts a missing token returns ErrNoToken before any
// request.
func TestSubmit_NoToken(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	deps.token = "" // simulate unconfigured

	cmd := newSubmitCmd(deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	opts := &submitOptions{file: path, yes: true, isTerminal: func() bool { return false }}
	err := runSubmit(cmd, deps, opts)
	if !errors.Is(err, osmerr.ErrNoToken) {
		t.Fatalf("want ErrNoToken, got %v", err)
	}
	if rec.postCount() != 0 {
		t.Errorf("submit POSTs = %d, want 0", rec.postCount())
	}
}

// TestSubmit_DuplicateReadsCleanly (T17/T19) asserts a 409 surfaces as a
// readable "already exists" error (naming existingThreatId), mapping to exit 1
// (not a UsageError).
func TestSubmit_DuplicateReadsCleanly(t *testing.T) {
	rec := &recorder{
		submitStatus: http.StatusConflict,
		submitResp:   `{"existingThreatId":"THREAT-999","message":"a report for this resource already exists"}`,
	}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv)
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	opts := &submitOptions{file: path, yes: true, isTerminal: func() bool { return false }}
	err := runSubmit(cmd, deps, opts)
	if err == nil {
		t.Fatal("want an error for a 409 duplicate, got nil")
	}
	var usage *osmerr.UsageError
	if errors.As(err, &usage) {
		t.Fatalf("409 must not be a UsageError (should map to exit 1), got %v", err)
	}
	msg := err.Error() + errBuf.String()
	if !strings.Contains(msg, "THREAT-999") && !strings.Contains(strings.ToLower(msg), "exist") {
		t.Errorf("duplicate error not readable (want existing id or 'exists'): %q / stderr=%q", err.Error(), errBuf.String())
	}
}

// --- Configured contact email ---

const configuredEmail = "you@example.com"

// contactEmailTranscript answers every wizard field blank except the required
// ones, with the given contact_email answer.
func contactEmailTranscript(t *testing.T, contactAnswer string) string {
	t.Helper()
	return interactiveTranscript(t,
		[]string{
			"package", "@acme/utils", "", "", // report_type..registry
			"",                     // publisher
			contactAnswer,          // contact_email
			"", "", "", "", "", "", // severity_level..tags
		},
		"steals npmrc", "http://evil.com")
}

// runInteractiveWithEmail is runInteractive with a configured default email.
func runInteractiveWithEmail(t *testing.T, email, transcript string) (report.Report, string) {
	t.Helper()
	deps := testDeps(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	deps.contactEmail = email
	cmd := newSubmitCmd(deps)
	var errBuf bytes.Buffer
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(transcript))

	r, err := collectInteractive(cmd, deps, &submitOptions{
		interactive: true,
		isTerminal:  func() bool { return true },
	})
	if err != nil {
		t.Fatalf("collectInteractive: %v", err)
	}
	return r, errBuf.String()
}

func TestSubmit_InteractiveContactEmailDefaultShown(t *testing.T) {
	_, prompts := runInteractiveWithEmail(t, configuredEmail, contactEmailTranscript(t, ""))
	if want := "(default: " + configuredEmail + ") > "; !strings.Contains(prompts, want) {
		t.Errorf("wizard output missing %q:\n%s", want, prompts)
	}
}

func TestSubmit_InteractiveContactEmailBlankTakesDefault(t *testing.T) {
	r, _ := runInteractiveWithEmail(t, configuredEmail, contactEmailTranscript(t, ""))
	if r.ContactEmail != configuredEmail {
		t.Errorf("contact_email = %q, want the configured %q", r.ContactEmail, configuredEmail)
	}
}

func TestSubmit_InteractiveContactEmailTypedOverridesDefault(t *testing.T) {
	r, _ := runInteractiveWithEmail(t, configuredEmail, contactEmailTranscript(t, "other@example.com"))
	if r.ContactEmail != "other@example.com" {
		t.Errorf("contact_email = %q, want the typed value", r.ContactEmail)
	}
}

func TestSubmit_InteractiveContactEmailUnsetHasNoDefault(t *testing.T) {
	r, prompts := runInteractiveWithEmail(t, "", contactEmailTranscript(t, ""))
	if r.ContactEmail != "" {
		t.Errorf("contact_email = %q, want empty when none is configured", r.ContactEmail)
	}
	// Only report_type shows a default.
	if n := strings.Count(prompts, "(default: "); n != 1 {
		t.Errorf("default prompts = %d, want 1 (report_type only):\n%s", n, prompts)
	}
}

// emitJSONContact runs --from-json with report on a deps carrying configured
// and returns the contact_email in the emitted request.
func emitJSONContact(t *testing.T, configured, reportJSON string) string {
	t.Helper()
	path := writeTempFile(t, "report.json", reportJSON)
	deps := testDeps(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	deps.contactEmail = configured
	cmd := newSubmitCmd(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	if err := runSubmit(cmd, deps, &submitOptions{fromJSON: path, emitJSON: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var req client.SubmitRequest
	if err := json.Unmarshal(out.Bytes(), &req); err != nil {
		t.Fatalf("emit-json output not valid JSON: %v\n%s", err, out.String())
	}
	return req.ContactEmail
}

const jsonReportBase = `"report_type":"package","resource_identifier":"evil-pkg","registry":"npm","threat_description":"bad"`

func TestSubmit_FromJSONFillsConfiguredContactEmail(t *testing.T) {
	got := emitJSONContact(t, configuredEmail, `{`+jsonReportBase+`}`)
	if got != configuredEmail {
		t.Errorf("contact_email = %q, want the configured %q", got, configuredEmail)
	}
}

func TestSubmit_FromJSONReportEmailWins(t *testing.T) {
	got := emitJSONContact(t, configuredEmail, `{`+jsonReportBase+`,"contact_email":"report@example.com"}`)
	if got != "report@example.com" {
		t.Errorf("contact_email = %q, want the report's own value", got)
	}
}

func TestSubmit_FromJSONNoConfiguredEmailStaysEmpty(t *testing.T) {
	if got := emitJSONContact(t, "", `{`+jsonReportBase+`}`); got != "" {
		t.Errorf("contact_email = %q, want empty", got)
	}
}

func TestSubmit_TemplateFileFillsConfiguredContactEmail(t *testing.T) {
	path := writeTempFile(t, "report.md", validTemplate)
	deps := testDeps(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	deps.contactEmail = configuredEmail
	cmd := newSubmitCmd(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	if err := runSubmit(cmd, deps, &submitOptions{file: path, emitJSON: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), `"contact_email": "`+configuredEmail+`"`) {
		t.Errorf("emitted request missing the configured email:\n%s", out.String())
	}
}
