package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/fieldse/osm-tools/internal/output"
)

// sweepServer returns a server that flags packages whose name is in malicious.
func sweepServer(t *testing.T, malicious map[string]bool, calls *int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			atomic.AddInt64(calls, 1)
		}
		name := r.URL.Query().Get("resource_identifier")
		if malicious[name] {
			w.Write([]byte(`{"malicious":true,"details":{"severity_level":"high"}}`))
			return
		}
		w.Write([]byte(`{"malicious":false}`))
	}))
}

func writeManifest(t *testing.T, deps map[string]string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"dependencies": deps})
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runSweepCmd(t *testing.T, deps *appDeps, args ...string) (string, error) {
	t.Helper()
	cmd := newSweepCmd(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func sweepDeps(t *testing.T, srv *httptest.Server) *appDeps {
	d := testDeps(srv)
	d.cachePath = filepath.Join(t.TempDir(), "cache.json")
	return d
}

func TestSweep_CleanExitsZero(t *testing.T) {
	srv := sweepServer(t, nil, nil)
	defer srv.Close()

	manifest := writeManifest(t, map[string]string{"express": "4.18.2", "lodash": "4.17.21"})
	out, err := runSweepCmd(t, sweepDeps(t, srv), "-f", manifest)
	if err != nil {
		t.Fatalf("clean sweep should not error, got %v", err)
	}
	if !strings.Contains(out, "express") || !strings.Contains(out, "0 malicious") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestSweep_FailOnAnyTriggersGate(t *testing.T) {
	srv := sweepServer(t, map[string]bool{"evil": true}, nil)
	defer srv.Close()

	manifest := writeManifest(t, map[string]string{"express": "4.18.2", "evil": "1.0.0"})
	_, err := runSweepCmd(t, sweepDeps(t, srv), "-f", manifest, "--fail-on-any")

	var gate *osmerr.GateTriggered
	if !errors.As(err, &gate) {
		t.Fatalf("want GateTriggered, got %v", err)
	}
	if len(gate.Hits) != 1 || !strings.Contains(gate.Hits[0], "evil") {
		t.Errorf("unexpected hits: %v", gate.Hits)
	}
}

func TestSweep_HitWithoutFailOnAnyExitsClean(t *testing.T) {
	srv := sweepServer(t, map[string]bool{"evil": true}, nil)
	defer srv.Close()

	manifest := writeManifest(t, map[string]string{"evil": "1.0.0"})
	out, err := runSweepCmd(t, sweepDeps(t, srv), "-f", manifest)
	if err != nil {
		t.Fatalf("without --fail-on-any, a hit should not error, got %v", err)
	}
	if !strings.Contains(out, "MALICIOUS") {
		t.Errorf("expected MALICIOUS in table:\n%s", out)
	}
}

func TestSweep_NetworkFailureExitsOperational(t *testing.T) {
	srv := sweepServer(t, nil, nil)
	url := srv.URL
	srv.Close() // closed → connection refused

	deps := testDeps(srv)
	deps.baseURL = url
	deps.cachePath = filepath.Join(t.TempDir(), "cache.json")

	manifest := writeManifest(t, map[string]string{"express": "4.18.2"})
	_, err := runSweepCmd(t, deps, "-f", manifest)
	if err == nil {
		t.Fatal("expected operational error on network failure")
	}
	var gate *osmerr.GateTriggered
	var usage *osmerr.UsageError
	if errors.As(err, &gate) || errors.As(err, &usage) {
		t.Errorf("network failure should be operational, got %T", err)
	}
}

func TestSweep_BadOutputFormat(t *testing.T) {
	srv := sweepServer(t, nil, nil)
	defer srv.Close()
	manifest := writeManifest(t, map[string]string{"express": "4.18.2"})

	_, err := runSweepCmd(t, sweepDeps(t, srv), "-f", manifest, "-o", "yaml")
	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want UsageError for bad format, got %v", err)
	}
}

func TestSweep_JSONOutput(t *testing.T) {
	srv := sweepServer(t, map[string]bool{"evil": true}, nil)
	defer srv.Close()
	manifest := writeManifest(t, map[string]string{"evil": "1.0.0"})

	out, err := runSweepCmd(t, sweepDeps(t, srv), "-f", manifest, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []output.SweepRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("output is not valid JSON array: %v\n%s", err, out)
	}
	if len(rows) != 1 || rows[0].Status != "MALICIOUS" {
		t.Errorf("unexpected rows: %+v", rows)
	}
}

func TestSweep_CacheAvoidsSecondCall(t *testing.T) {
	var calls int64
	srv := sweepServer(t, nil, &calls)
	defer srv.Close()

	deps := sweepDeps(t, srv)
	manifest := writeManifest(t, map[string]string{"express": "4.18.2"})

	if _, err := runSweepCmd(t, deps, "-f", manifest); err != nil {
		t.Fatal(err)
	}
	// Second sweep reuses the same cache path → served from cache, no new call.
	if _, err := runSweepCmd(t, deps, "-f", manifest); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("API called %d times, want 1 (second sweep should hit cache)", calls)
	}
}
