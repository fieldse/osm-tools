package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/exitcode"
	"github.com/fieldse/osm-tools/internal/osmerr"
)

// Response bodies use the shapes observed live on 2026-10-25 (plan, "API facts").
const (
	fixtureHitExactVersion = `{"malicious":true,"version":"1.14.1","osm_url":"https://opensourcemalware.com/npm/axios","threat_count":1,"details":{"threat_id":"a5b0c3d2-7f41-4e8a-9b1c-2d3e4f5a6b7c","severity_level":"critical","description":"Compromised maintainer account published a credential-stealing postinstall script.","version_info":"1.14.1, 0.30.4"}}`

	fixtureHitNoVersion = `{"malicious":true,"version":null,"osm_url":"https://opensourcemalware.com/npm/axios","threat_count":1,"details":{"threat_id":"a5b0c3d2-7f41-4e8a-9b1c-2d3e4f5a6b7c","severity_level":"critical","description":"Compromised maintainer account published a credential-stealing postinstall script.","version_info":"1.14.1, 0.30.4"}}`

	fixtureHitVersionInfoNull = `{"malicious":true,"version":null,"osm_url":"https://opensourcemalware.com/npm/evil-pkg","threat_count":1,"details":{"threat_id":"0e9d8c7b-6a5f-4e3d-2c1b-0a9f8e7d6c5b","severity_level":"high","description":"Typosquat that exfiltrates environment variables.","version_info":null}}`

	fixtureHitVersionInfoAll = `{"malicious":true,"version":null,"osm_url":"https://opensourcemalware.com/npm/evil-pkg","threat_count":2,"details":{"threat_id":"0e9d8c7b-6a5f-4e3d-2c1b-0a9f8e7d6c5b","severity_level":"high","description":"Typosquat that exfiltrates environment variables.","version_info":"all"}}`

	fixtureWarningDetailsNull = `{"malicious":false,"version":"^1.14.0","warning":"This package has known malicious versions","known_malicious_versions":["1.14.1, 0.30.4"],"osm_url":"https://opensourcemalware.com/npm/axios","details":null}`

	fixtureNotFound = `{"malicious":false,"message":"Resource not found in malicious database","report_type":"package","resource_identifier":"left-pad-ok","ecosystem":"npm"}`

	fixture429PerMinute = `{"error":"Rate limit exceeded. Maximum 60 requests per minute (standard tier)."}`

	fixture429Daily = `{"error":"Daily quota exceeded: 2000/2000 requests used. Quota resets at 00:00 UTC.","tier":"free","limit":2000,"used":2000}`
)

// recordedRequest is one request the fake OSM server received.
type recordedRequest struct {
	Path  string
	Query string
}

// recordingServer is an httptest server that logs every request and answers
// the nth request (0-based) with respond(n).
type recordingServer struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []recordedRequest
}

type cannedResponse struct {
	status     int
	retryAfter string // "" means no Retry-After header
	body       string
}

func newRecordingServer(t *testing.T, respond func(n int) cannedResponse) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		n := len(rs.reqs)
		rs.reqs = append(rs.reqs, recordedRequest{Path: r.URL.Path, Query: r.URL.RawQuery})
		rs.mu.Unlock()

		resp := respond(n)
		w.Header().Set("Content-Type", "application/json")
		if resp.retryAfter != "" {
			w.Header().Set("Retry-After", resp.retryAfter)
		}
		w.WriteHeader(resp.status)
		_, _ = w.Write([]byte(resp.body))
	}))
	t.Cleanup(rs.Close)
	return rs
}

func (rs *recordingServer) requests() []recordedRequest {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]recordedRequest, len(rs.reqs))
	copy(out, rs.reqs)
	return out
}

func newAcceptanceClient(srv *recordingServer) *client.Client {
	return client.New(srv.URL, "osm_test", client.NewRateLimitedClient(client.NewLimiter(100000)))
}

var axiosQuery = client.Query{Type: "package", Identifier: "axios", Ecosystem: "npm", Version: "1.14.1"}

// assertAllRequestsIdentical checks that every request (including retries)
// went to /check-malicious with the same query as the first.
func assertAllRequestsIdentical(t *testing.T, reqs []recordedRequest) {
	t.Helper()
	for i, r := range reqs {
		if !strings.HasSuffix(r.Path, "/check-malicious") {
			t.Errorf("request %d path = %q, want .../check-malicious", i, r.Path)
		}
		if r.Query != reqs[0].Query {
			t.Errorf("request %d query = %q, want same as request 0 (%q)", i, r.Query, reqs[0].Query)
		}
	}
}

// AT-11.1: a 429 with Retry-After: 0 followed by a 200 is retried once and
// Check returns the 200 body; exactly 2 identical requests are sent.
func TestAcceptanceRetry429ThenSuccess(t *testing.T) {
	srv := newRecordingServer(t, func(n int) cannedResponse {
		if n == 0 {
			return cannedResponse{status: http.StatusTooManyRequests, retryAfter: "0", body: fixture429PerMinute}
		}
		return cannedResponse{status: http.StatusOK, body: fixtureHitExactVersion}
	})

	res, err := newAcceptanceClient(srv).Check(context.Background(), axiosQuery)
	if err != nil {
		t.Fatalf("Check after one 429 returned error: %v", err)
	}
	if !res.Malicious {
		t.Errorf("Malicious = false, want true (decoded from the 200 that followed the 429)")
	}
	if res.Details.SeverityLevel != "critical" {
		t.Errorf("Details.SeverityLevel = %q, want critical", res.Details.SeverityLevel)
	}

	reqs := srv.requests()
	if len(reqs) != 2 {
		t.Fatalf("server saw %d requests, want exactly 2 (1 + 1 retry): %+v", len(reqs), reqs)
	}
	assertAllRequestsIdentical(t, reqs)
}

// AT-11.2: a server that always returns 429 with Retry-After: 0 yields an
// *osmerr.APIError with StatusCode 429 after exactly 4 requests (1 + 3 retries).
func TestAcceptanceRetry429Exhausted(t *testing.T) {
	srv := newRecordingServer(t, func(int) cannedResponse {
		return cannedResponse{status: http.StatusTooManyRequests, retryAfter: "0", body: fixture429PerMinute}
	})

	_, err := newAcceptanceClient(srv).Check(context.Background(), axiosQuery)
	if err == nil {
		t.Fatal("Check returned nil error against a server that always answers 429")
	}
	var apiErr *osmerr.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is %T (%v), want *osmerr.APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("APIError.StatusCode = %d, want 429", apiErr.StatusCode)
	}
	if got := exitcode.FromError(err); got != exitcode.Operational {
		t.Errorf("exit code = %d, want %d (operational)", got, exitcode.Operational)
	}

	reqs := srv.requests()
	if len(reqs) != 4 {
		t.Fatalf("server saw %d requests, want exactly 4 (1 + 3 retries)", len(reqs))
	}
	assertAllRequestsIdentical(t, reqs)
}

// AT-11.3: a daily-quota 429 is not retried, even with Retry-After: 0; the
// error comes back after exactly 1 request and its text contains "Daily quota".
// regression guard
func TestAcceptanceDailyQuota429NotRetried(t *testing.T) {
	srv := newRecordingServer(t, func(int) cannedResponse {
		return cannedResponse{status: http.StatusTooManyRequests, retryAfter: "0", body: fixture429Daily}
	})

	_, err := newAcceptanceClient(srv).Check(context.Background(), axiosQuery)
	if err == nil {
		t.Fatal("Check returned nil error on a daily-quota 429")
	}
	if !strings.Contains(err.Error(), "Daily quota") {
		t.Errorf("error text %q does not contain %q", err.Error(), "Daily quota")
	}
	if got := exitcode.FromError(err); got != exitcode.Operational {
		t.Errorf("exit code = %d, want %d (operational)", got, exitcode.Operational)
	}
	if n := len(srv.requests()); n != 1 {
		t.Errorf("server saw %d requests, want exactly 1 (daily quota must not be retried)", n)
	}
}

// AT-11.4: a context that ends while Check waits out a Retry-After: 30 makes
// Check return promptly (under 2s) with a context error, after 1 request.
func TestAcceptanceRetryWaitHonoursContext(t *testing.T) {
	tests := []struct {
		name   string
		newCtx func() (context.Context, context.CancelFunc)
	}{
		{
			name: "deadline expires during wait",
			newCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 300*time.Millisecond)
			},
		},
		{
			name: "explicit cancel during wait",
			newCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				timer := time.AfterFunc(300*time.Millisecond, cancel)
				return ctx, func() { timer.Stop(); cancel() }
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newRecordingServer(t, func(int) cannedResponse {
				return cannedResponse{status: http.StatusTooManyRequests, retryAfter: "30", body: fixture429PerMinute}
			})
			ctx, cancel := tt.newCtx()
			defer cancel()

			start := time.Now()
			_, err := newAcceptanceClient(srv).Check(ctx, axiosQuery)
			elapsed := time.Since(start)

			if elapsed >= 2*time.Second {
				t.Errorf("Check took %s after the context ended, want under 2s", elapsed)
			}
			if err == nil {
				t.Fatal("Check returned nil error with a cancelled context")
			}
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
				t.Errorf("error = %v (%T), want one wrapping context.DeadlineExceeded or context.Canceled", err, err)
			}
			if n := len(srv.requests()); n != 1 {
				t.Errorf("server saw %d requests, want exactly 1 (cancelled before the retry)", n)
			}
		})
	}
}

// AT-11.5: a 500 is not retried; Check returns an *osmerr.APIError with
// status 500 after exactly 1 request.
// regression guard
func TestAcceptanceServerErrorNotRetried(t *testing.T) {
	srv := newRecordingServer(t, func(int) cannedResponse {
		return cannedResponse{status: http.StatusInternalServerError, retryAfter: "0", body: `{"error":"internal"}`}
	})

	_, err := newAcceptanceClient(srv).Check(context.Background(), axiosQuery)
	var apiErr *osmerr.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is %T (%v), want *osmerr.APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("APIError.StatusCode = %d, want 500", apiErr.StatusCode)
	}
	if n := len(srv.requests()); n != 1 {
		t.Errorf("server saw %d requests, want exactly 1 (5xx must not be retried)", n)
	}
}

// AT-8.1, AT-8.2: Check decodes every live response shape without error,
// including "version":null, "details.version_info":null, "details":null and
// "known_malicious_versions", and keeps the fields that exist today.
// regression guard
func TestAcceptanceCheckDecodesLiveShapes(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantMalicious bool
		wantThreats   int
		wantSeverity  string
		wantDescPart  string
	}{
		{"AT-8.1 hit with exact version", fixtureHitExactVersion, true, 1, "critical", "credential-stealing"},
		{"AT-8.1 hit with version null", fixtureHitNoVersion, true, 1, "critical", "credential-stealing"},
		{"AT-8.1 hit with version_info null", fixtureHitVersionInfoNull, true, 1, "high", "Typosquat"},
		{"AT-8.1 hit with version_info all", fixtureHitVersionInfoAll, true, 2, "high", "Typosquat"},
		{"AT-8.2 warning with details null", fixtureWarningDetailsNull, false, 0, "", ""},
		{"not found", fixtureNotFound, false, 0, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newRecordingServer(t, func(int) cannedResponse {
				return cannedResponse{status: http.StatusOK, body: tt.body}
			})

			res, err := newAcceptanceClient(srv).Check(context.Background(), axiosQuery)
			if err != nil {
				t.Fatalf("Check failed to decode the live shape: %v", err)
			}
			if res.Malicious != tt.wantMalicious {
				t.Errorf("Malicious = %v, want %v", res.Malicious, tt.wantMalicious)
			}
			if res.ThreatCount != tt.wantThreats {
				t.Errorf("ThreatCount = %d, want %d", res.ThreatCount, tt.wantThreats)
			}
			// Details is only inspected on hits, so a pointer Details that is nil
			// for "details":null stays valid.
			if tt.wantMalicious {
				if res.Details.SeverityLevel != tt.wantSeverity {
					t.Errorf("Details.SeverityLevel = %q, want %q", res.Details.SeverityLevel, tt.wantSeverity)
				}
				if !strings.Contains(res.Details.Description, tt.wantDescPart) {
					t.Errorf("Details.Description = %q, want it to contain %q", res.Details.Description, tt.wantDescPart)
				}
			}
			if n := len(srv.requests()); n != 1 {
				t.Errorf("server saw %d requests, want 1", n)
			}
		})
	}
}
