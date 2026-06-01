//go:build integration

// Package tests holds end-to-end and timing checks that drive the built binary
// or exercise real timing. Run with: go test -tags integration ./tests/...
package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fieldse/osm-tools/internal/client"
)

// buildBinary compiles the osm binary once and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "osm")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/fieldse/osm-tools").CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

// run executes the binary against the fake API, returning stdout+stderr and the
// exit code. HOME is isolated so it never touches the real ~/.osm.
func run(t *testing.T, bin, baseURL string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(),
		"OSM_BASE_URL="+baseURL,
		"OSM_API_KEY=osm_test",
		"HOME="+t.TempDir(),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	t.Fatalf("run failed: %v\n%s", err, out)
	return "", -1
}

func TestSmoke_Check(t *testing.T) {
	bin := buildBinary(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"malicious":true,"severity_level":"critical"}`))
	}))
	defer srv.Close()

	out, code := run(t, bin, srv.URL, "check", "evil.com")
	if code != 0 {
		t.Errorf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "MALICIOUS") {
		t.Errorf("missing verdict:\n%s", out)
	}
}

func TestSmoke_SweepGate(t *testing.T) {
	bin := buildBinary(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource_identifier") == "evil" {
			w.Write([]byte(`{"malicious":true,"severity_level":"high"}`))
			return
		}
		w.Write([]byte(`{"malicious":false}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"dependencies":{"evil":"1.0.0","express":"4.18.2"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Without --fail-on-any: hit shown, exit 0.
	out, code := run(t, bin, srv.URL, "sweep", "-f", manifest)
	if code != 0 {
		t.Errorf("plain sweep exit = %d, want 0\n%s", code, out)
	}
	// With --fail-on-any: gate fires, exit 3.
	out, code = run(t, bin, srv.URL, "sweep", "-f", manifest, "--fail-on-any")
	if code != 3 {
		t.Errorf("gate exit = %d, want 3\n%s", code, out)
	}
}

func TestSmoke_Latest(t *testing.T) {
	bin := buildBinary(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ecosystem":"npm","package":"bad","version":"1.0.0","threat_id":"t-1"}]`))
	}))
	defer srv.Close()

	out, code := run(t, bin, srv.URL, "latest", "-e", "npm")
	if code != 0 {
		t.Errorf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, `"npm"`) {
		t.Errorf("missing grouped output:\n%s", out)
	}
}

func TestSmoke_UnknownEcosystemExits2(t *testing.T) {
	bin := buildBinary(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, code := run(t, bin, srv.URL, "latest", "-e", "bogus")
	if code != 2 {
		t.Errorf("exit = %d, want 2 (usage)", code)
	}
}

// TestRateLimiterPacing drives concurrent requests through the real rate-limited
// transport and asserts the limiter paces them (no burst). Uses a fast rate so
// the test is quick.
func TestRateLimiterPacing(t *testing.T) {
	const rpm = 600 // 10 req/s → 100ms spacing
	var mu sync.Mutex
	var times []time.Time

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		w.Write([]byte(`{"malicious":false}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "osm_test", client.NewRateLimitedClient(client.NewLimiter(rpm)))

	const n = 8
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Check(context.Background(), client.Query{Type: "package", Identifier: "x", Ecosystem: "npm"})
		}()
	}
	wg.Wait()

	if len(times) != n {
		t.Fatalf("got %d requests, want %d", len(times), n)
	}
	// n requests at 10/s with burst 1 should take at least (n-1)*100ms.
	minElapsed := time.Duration(n-1) * 100 * time.Millisecond
	if elapsed := time.Since(start); elapsed < minElapsed {
		t.Errorf("completed in %v, faster than limiter floor %v — limiter not pacing", elapsed, minElapsed)
	}
}
