package cmd

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// TestSubmit_NonTTYRefuseMakesNoRequest_F1 asserts the non-TTY-without-yes
// refusal short-circuits BEFORE the best-effort dedupe GET — the safety
// invariant is "no request" on this path, not merely "no POST". The base test
// only checked POSTs; this checks GETs too.
func TestSubmit_NonTTYRefuseMakesNoRequest_F1(t *testing.T) {
	rec := &recorder{}
	srv := newRecordingServer(rec)
	defer srv.Close()

	path := writeTempFile(t, "report.md", validTemplate)

	deps := testDeps(srv) // token IS configured — the dedupe GET would otherwise fire
	cmd := newSubmitCmd(deps)
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	opts := &submitOptions{file: path, isTerminal: func() bool { return false }}
	if err := runSubmit(cmd, deps, opts); err == nil {
		t.Fatal("want a usage error on non-TTY without --yes")
	}

	rec.mu.Lock()
	gets, posts := rec.gets, rec.posts
	rec.mu.Unlock()
	if gets != 0 {
		t.Errorf("dedupe GETs = %d, want 0 (must refuse before any network)", gets)
	}
	if posts != 0 {
		t.Errorf("submit POSTs = %d, want 0", posts)
	}
}

// TestSubmit_DistinctErrorMessages_F7 asserts 403 (new-user cap) and 429
// (rate/submission cap) surface distinct, readable messages — not a raw status
// dump — per spec T17.
func TestSubmit_DistinctErrorMessages_F7(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantWord string
	}{
		{"403 new-user cap", http.StatusForbidden, `{"unverified_reports":3}`, "verif"},
		{"429 rate/submission cap", http.StatusTooManyRequests, "too many", "rate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{submitStatus: tt.status, submitResp: tt.body}
			srv := newRecordingServer(rec)
			defer srv.Close()

			path := writeTempFile(t, "report.md", validTemplate)
			deps := testDeps(srv)
			cmd := newSubmitCmd(deps)
			var out, errBuf bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errBuf)

			opts := &submitOptions{file: path, yes: true, isTerminal: func() bool { return true }}
			err := runSubmit(cmd, deps, opts)
			if err == nil {
				t.Fatalf("want an error for status %d", tt.status)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantWord) {
				t.Errorf("error %q does not explain the %d cap (want it to mention %q)", err.Error(), tt.status, tt.wantWord)
			}
		})
	}
}
