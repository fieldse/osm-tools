package client

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// newTestClient returns a Client pointed at the given server with a permissive
// limiter so tests don't wait on the rate bucket.
func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	httpClient := NewRateLimitedClient(NewLimiter(100000))
	return New(srv.URL, "osm_test", httpClient)
}

func TestCheck_MaliciousTrue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("report_type"); got != "package" {
			t.Errorf("report_type = %q, want package", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer osm_test" {
			t.Errorf("auth header = %q", got)
		}
		w.Write([]byte(`{"malicious":true,"details":{"id":"t-1","severity_level":"critical"}}`))
	}))
	defer srv.Close()

	res, err := newTestClient(t, srv).Check(context.Background(), Query{Type: "package", Identifier: "evil", Ecosystem: "npm"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Malicious || res.Details.SeverityLevel != "critical" || res.Details.ID != "t-1" {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestCheck_MaliciousFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"malicious":false}`))
	}))
	defer srv.Close()

	res, err := newTestClient(t, srv).Check(context.Background(), Query{Type: "package", Identifier: "express", Ecosystem: "npm"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Malicious {
		t.Error("expected malicious=false")
	}
}

func TestCheck_DockerMapsToContainer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("report_type"); got != "container" {
			t.Errorf("report_type = %q, want container (docker should map)", got)
		}
		w.Write([]byte(`{"malicious":false}`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv).Check(context.Background(), Query{Type: "docker", Identifier: "nginx:latest"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheck_ErrorStatuses(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		retryAfter string
		check      func(*osmerr.APIError) bool
	}{
		{"401 auth", http.StatusUnauthorized, "", (*osmerr.APIError).IsAuth},
		{"403 auth", http.StatusForbidden, "", (*osmerr.APIError).IsAuth},
		{"429 rate limit", http.StatusTooManyRequests, "30", (*osmerr.APIError).IsRateLimit},
		{"500 server", http.StatusInternalServerError, "", (*osmerr.APIError).IsServer},
		{"503 server", http.StatusServiceUnavailable, "", (*osmerr.APIError).IsServer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.retryAfter != "" {
					w.Header().Set("Retry-After", tt.retryAfter)
				}
				w.WriteHeader(tt.status)
				w.Write([]byte("error body"))
			}))
			defer srv.Close()

			_, err := newTestClient(t, srv).Check(context.Background(), Query{Type: "package", Identifier: "x", Ecosystem: "npm"})
			var apiErr *osmerr.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("want *APIError, got %T: %v", err, err)
			}
			if apiErr.StatusCode != tt.status {
				t.Errorf("status = %d, want %d", apiErr.StatusCode, tt.status)
			}
			if !tt.check(apiErr) {
				t.Errorf("classification helper returned false for status %d", tt.status)
			}
			if tt.retryAfter != "" && apiErr.RetryAfter != tt.retryAfter {
				t.Errorf("RetryAfter = %q, want %q", apiErr.RetryAfter, tt.retryAfter)
			}
		})
	}
}

func TestCheck_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv).Check(context.Background(), Query{Type: "package", Identifier: "x", Ecosystem: "npm"})
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
	// A decode error is not an APIError.
	var apiErr *osmerr.APIError
	if errors.As(err, &apiErr) {
		t.Error("decode error should not be an APIError")
	}
}

func TestCheck_NetworkFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // close immediately so requests fail to connect

	_, err := New(url, "osm_test", NewRateLimitedClient(NewLimiter(100000))).
		Check(context.Background(), Query{Type: "package", Identifier: "x", Ecosystem: "npm"})
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
}

func TestCheck_DebugLogging(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"malicious":false}`))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	c := newTestClient(t, srv)
	c.SetDebug(&buf)

	if _, err := c.Check(context.Background(), Query{Type: "package", Identifier: "express", Ecosystem: "npm"}); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "→ GET") || !strings.Contains(out, "/check-malicious") {
		t.Errorf("debug missing request line:\n%s", out)
	}
	if !strings.Contains(out, "← 200") {
		t.Errorf("debug missing response status:\n%s", out)
	}
	// The token must never be logged.
	if strings.Contains(out, "osm_test") || strings.Contains(out, "Bearer") {
		t.Errorf("debug leaked the token:\n%s", out)
	}
}

func TestQueryLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("ecosystem"); got != "npm" {
			t.Errorf("ecosystem = %q, want npm", got)
		}
		w.Write([]byte(`{"ecosystem":"npm","count":1,"threats":[{"id":"t-9","package_name":"evil","version_info":"1.0.0"}]}`))
	}))
	defer srv.Close()

	res, err := newTestClient(t, srv).QueryLatest(context.Background(), "npm")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].PackageName != "evil" || res[0].ID != "t-9" {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestCheck_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"malicious":false}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	_, err := newTestClient(t, srv).Check(ctx, Query{Type: "package", Identifier: "x", Ecosystem: "npm"})
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
}
