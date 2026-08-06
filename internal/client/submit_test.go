package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// Tests for the submit client path. Run against an httptest server via
// newTestClient, mirroring client_test.go. Case IDs map to
// docs/submit-report-spec.md.

// TestSubmitThreat_Success (T1) asserts a valid request produces exactly one
// POST /submit-threat-report and returns threat_id + "pending" status from 201.
func TestSubmitThreat_Success(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/submit-threat-report" {
			t.Errorf("path = %q, want /submit-threat-report", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer osm_test" {
			t.Errorf("auth header = %q, want Bearer osm_test", got)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"threat_id":"th-1","status":"pending","message":"queued for review"}`))
	}))
	defer srv.Close()

	res, err := newTestClient(t, srv).SubmitThreat(context.Background(), SubmitRequest{
		ReportType:         "package",
		ResourceIdentifier: "evil",
		ThreatDescription:  "malware",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ThreatID != "th-1" {
		t.Errorf("ThreatID = %q, want th-1", res.ThreatID)
	}
	if res.Status != "pending" {
		t.Errorf("Status = %q, want pending", res.Status)
	}
	if hits != 1 {
		t.Errorf("handler hit %d times, want 1", hits)
	}
}

// TestSubmitThreat_WirePayload (T2) captures the request body and asserts the
// documented field names — registry (not ecosystem), evidence_references as a
// pipe-delimited string — are on the wire.
func TestSubmitThreat_WirePayload(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("unmarshal body: %v (raw: %s)", err, raw)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"threat_id":"th-2","status":"pending"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv).SubmitThreat(context.Background(), SubmitRequest{
		ReportType:         "package",
		ResourceIdentifier: "evil",
		ThreatDescription:  "malware",
		Registry:           "npm",
		EvidenceReferences: "a|b|c",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := body["ecosystem"]; ok {
		t.Error("body has key \"ecosystem\"; want \"registry\"")
	}
	if got, ok := body["registry"]; !ok || got != "npm" {
		t.Errorf("body[registry] = %v (present=%v), want npm", got, ok)
	}
	ev, ok := body["evidence_references"]
	if !ok {
		t.Fatal("body missing evidence_references")
	}
	if _, isString := ev.(string); !isString {
		t.Errorf("evidence_references is %T, want a pipe-delimited string", ev)
	}
	if ev != "a|b|c" {
		t.Errorf("evidence_references = %v, want a|b|c", ev)
	}
}

// TestSubmitThreat_DockerMapsToContainer (T2) asserts ReportType "docker" is
// sent as "container".
func TestSubmitThreat_DockerMapsToContainer(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("unmarshal body: %v (raw: %s)", err, raw)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"threat_id":"th-3","status":"pending"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv).SubmitThreat(context.Background(), SubmitRequest{
		ReportType:         "docker",
		ResourceIdentifier: "nginx:latest",
		ThreatDescription:  "malware",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := body["report_type"]; got != "container" {
		t.Errorf("report_type = %v, want container (docker should map)", got)
	}
}

// TestSubmitThreat_ErrorStatuses (T17) covers 401, 403 (new-user cap), 409
// (duplicate), 429, and a 5xx → *osmerr.APIError with the right StatusCode and
// classification, never a raw crash. For 409 the response body carries
// existingThreatId, which the APIError must preserve.
func TestSubmitThreat_ErrorStatuses(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		check      func(*osmerr.APIError) bool
		wantInBody string
	}{
		{"401 auth", http.StatusUnauthorized, "unauthorized", (*osmerr.APIError).IsAuth, ""},
		{"403 auth", http.StatusForbidden, "forbidden: new-user cap", (*osmerr.APIError).IsAuth, ""},
		{"409 duplicate", http.StatusConflict, `{"existingThreatId":"th-dup-1"}`, nil, "existingThreatId"},
		{"429 rate limit", http.StatusTooManyRequests, "slow down", (*osmerr.APIError).IsRateLimit, ""},
		{"500 server", http.StatusInternalServerError, "boom", (*osmerr.APIError).IsServer, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			_, err := newTestClient(t, srv).SubmitThreat(context.Background(), SubmitRequest{
				ReportType:         "package",
				ResourceIdentifier: "evil",
				ThreatDescription:  "malware",
			})
			var apiErr *osmerr.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("want *APIError, got %T: %v", err, err)
			}
			if apiErr.StatusCode != tt.status {
				t.Errorf("status = %d, want %d", apiErr.StatusCode, tt.status)
			}
			if tt.check != nil && !tt.check(apiErr) {
				t.Errorf("classification helper returned false for status %d", tt.status)
			}
			if tt.wantInBody != "" && !strings.Contains(apiErr.Body, tt.wantInBody) {
				t.Errorf("APIError.Body = %q, want it to contain %q", apiErr.Body, tt.wantInBody)
			}
		})
	}
}

// TestSubmitThreat_ContextCancelled (T17/robustness) asserts a cancelled
// context surfaces an error rather than hanging.
func TestSubmitThreat_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"threat_id":"th-x","status":"pending"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	_, err := newTestClient(t, srv).SubmitThreat(ctx, SubmitRequest{
		ReportType:         "package",
		ResourceIdentifier: "evil",
		ThreatDescription:  "malware",
	})
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
}
