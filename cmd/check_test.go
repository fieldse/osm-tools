package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/infer"
	"github.com/fieldse/osm-tools/internal/osmerr"
)

// testDeps builds appDeps wired to the given server with a permissive limiter.
func testDeps(srv *httptest.Server) *appDeps {
	limiter := client.NewLimiter(100000)
	return &appDeps{
		token:      "osm_test",
		baseURL:    srv.URL,
		limiter:    limiter,
		httpClient: client.NewRateLimitedClient(limiter),
	}
}

// runCheckCmd executes the check command against deps, capturing stdout.
func runCheckCmd(t *testing.T, deps *appDeps, args ...string) (string, error) {
	t.Helper()
	cmd := newCheckCmd(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestCheckCmd_MaliciousPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"malicious":true,"severity_level":"high","description":"bad"}`))
	}))
	defer srv.Close()

	out, err := runCheckCmd(t, testDeps(srv), "evil", "-e", "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "MALICIOUS") || !strings.Contains(out, "high") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestCheckCmd_PackageMissingEcosystem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, err := runCheckCmd(t, testDeps(srv), "express")
	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want UsageError, got %v", err)
	}
}

func TestCheckCmd_NoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	deps := testDeps(srv)
	deps.token = "" // simulate unconfigured

	_, err := runCheckCmd(t, deps, "evil.com")
	if !errors.Is(err, osmerr.ErrNoToken) {
		t.Fatalf("want ErrNoToken, got %v", err)
	}
}

func TestResolveCheckType(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		typeFlag  string
		ecosystem string
		want      string
		wantErr   bool
	}{
		{"package needs ecosystem error", "express", "", "", "", true},
		{"package with ecosystem", "express", "", "npm", infer.TypePackage, false},
		{"domain inferred, no ecosystem needed", "evil.com", "", "", infer.TypeDomain, false},
		{"ip inferred", "1.2.3.4", "", "", infer.TypeIP, false},
		{"explicit type override", "express", "domain", "", infer.TypeDomain, false},
		{"explicit package still needs ecosystem", "whatever", "package", "", "", true},
		{"unknown type flag", "x", "bogus", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveCheckType(tt.id, tt.typeFlag, tt.ecosystem)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got type %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
