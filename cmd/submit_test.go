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
		r, err := collectReport(cmd, opts)
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

	r, err := collectInteractive(cmd, &submitOptions{
		interactive: true,
		isTerminal:  func() bool { return true },
	})
	if err != nil {
		t.Fatalf("collectInteractive: %v", err)
	}
	return r, errBuf.String()
}

// TestSubmit_InteractiveDefaults asserts a bare Enter on report_type and
// registry takes the package/npm defaults rather than submitting empty fields.
func TestSubmit_InteractiveDefaults(t *testing.T) {
	// report_type and registry left blank; everything else answered or skipped.
	transcript := interactiveTranscript(t,
		[]string{
			"",                             // report_type   -> default package
			"@acme/utils",                  // resource_identifier
			"",                             // package_name
			"",                             // registry      -> default npm
			"", "", "", "", "", "", "", "", // publisher..tags
		},
		"steals npmrc", "http://evil.com")

	r, _ := runInteractive(t, transcript)

	if r.Type != report.TypePackage {
		t.Errorf("report_type = %q, want the %q default on blank input", r.Type, report.TypePackage)
	}
	if r.Registry != "npm" {
		t.Errorf("registry = %q, want the \"npm\" default on blank input", r.Registry)
	}
}

// TestSubmit_InteractiveRegistryDefaultOnlyForPackages asserts a non-package
// report does not get npm pre-filled — a domain report has no registry, so a
// default there would invite a wrong answer rather than save a keystroke.
func TestSubmit_InteractiveRegistryDefaultOnlyForPackages(t *testing.T) {
	transcript := interactiveTranscript(t,
		[]string{
			"domain",                       // report_type
			"evil.com",                     // resource_identifier
			"",                             // package_name
			"",                             // registry -> must stay empty
			"", "", "", "", "", "", "", "", // publisher..tags
		},
		"hosts malware", "")

	r, _ := runInteractive(t, transcript)

	if r.Registry != "" {
		t.Errorf("registry = %q, want empty for a domain report (npm default must not apply)", r.Registry)
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
		"> package",                                         // default shown on the input line
		"> npm",                                             // registry default on the input line
		"YYYY-MM-DD",                                        // date format hint
		"Example:",                                          // block examples
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt transcript missing %q:\n%s", want, out)
		}
	}
}

// TestSubmit_InteractiveFirstSeenDefaultsToday asserts a blank first_seen takes
// today's date in YYYY-MM-DD form, via the clock seam so the assertion is
// deterministic.
func TestSubmit_InteractiveFirstSeenDefaultsToday(t *testing.T) {
	fixed := time.Date(2026, 7, 16, 9, 30, 0, 0, time.UTC)

	transcript := interactiveTranscript(t,
		[]string{
			"package", "@acme/utils", "", "",
			"", "", "", "", // publisher..version_info
			"",     // first_seen -> today's default
			"",     // last_seen
			"", "", // osv_advisory_url, tags
		},
		"steals npmrc", "")

	deps := testDeps(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	cmd := newSubmitCmd(deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader(transcript))

	r, err := collectInteractive(cmd, &submitOptions{
		interactive: true,
		isTerminal:  func() bool { return true },
		now:         func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatalf("collectInteractive: %v", err)
	}
	if r.FirstSeen != "2026-07-16" {
		t.Errorf("first_seen = %q, want today's date %q on blank input", r.FirstSeen, "2026-07-16")
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

// TestSubmit_ConflictingModesError (T7) asserts FILE+--from-json, FILE+-i, and
// -i+--from-json each return a UsageError.
func TestSubmit_ConflictingModesError(t *testing.T) {
	deps := testDeps(httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))

	cases := []struct {
		name string
		opts *submitOptions
	}{
		{"file+json", &submitOptions{file: "x.md", fromJSON: "y.json"}},
		{"file+interactive", &submitOptions{file: "x.md", interactive: true, isTerminal: func() bool { return true }}},
		{"interactive+json", &submitOptions{interactive: true, fromJSON: "y.json", isTerminal: func() bool { return true }}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newSubmitCmd(deps)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetIn(strings.NewReader(""))
			_, err := collectReport(cmd, tc.opts)
			var usage *osmerr.UsageError
			if !errors.As(err, &usage) {
				t.Fatalf("want UsageError, got %v", err)
			}
		})
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
