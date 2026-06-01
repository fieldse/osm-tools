package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/ecosystem"
	"github.com/fieldse/osm-tools/internal/osmerr"
)

func TestSelectEcosystems(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		wantLen int
		wantErr bool
	}{
		{"empty means all", "", len(ecosystem.All()), false},
		{"single", "npm", 1, false},
		{"multiple", "npm,pypi,maven", 3, false},
		{"whitespace tolerated", " npm , pypi ", 2, false},
		{"unknown errors", "npm,bogus", 0, true},
		{"only commas errors", ",,", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectEcosystems(tt.flag)
			if tt.wantErr {
				var usage *osmerr.UsageError
				if !errors.As(err, &usage) {
					t.Fatalf("want UsageError, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Errorf("got %d ecosystems, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestLatest_FetchAndGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eco := r.URL.Query().Get("ecosystem")
		w.Write([]byte(`[{"ecosystem":"` + eco + `","package":"evil-` + eco + `","version":"1.0.0","threat_id":"t-` + eco + `"}]`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "osm_test", client.NewRateLimitedClient(client.NewLimiter(100000)))
	grouped, err := fetchLatest(context.Background(), c, []string{"npm", "pypi"})
	if err != nil {
		t.Fatal(err)
	}
	if len(grouped["npm"]) != 1 || grouped["npm"][0].Package != "evil-npm" {
		t.Errorf("npm group wrong: %+v", grouped["npm"])
	}
	if len(grouped["pypi"]) != 1 || grouped["pypi"][0].Package != "evil-pypi" {
		t.Errorf("pypi group wrong: %+v", grouped["pypi"])
	}
}

func TestLatestCmd_JSONOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ecosystem":"npm","package":"evil","version":"1.0.0","threat_id":"t-1"}]`))
	}))
	defer srv.Close()

	cmd := newLatestCmd(testDeps(srv))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-e", "npm"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	var grouped map[string][]client.LatestThreat
	if err := json.Unmarshal(out.Bytes(), &grouped); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out.String())
	}
	if len(grouped["npm"]) != 1 {
		t.Errorf("unexpected output: %+v", grouped)
	}
}

func TestLatestCmd_UnknownEcosystem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	cmd := newLatestCmd(testDeps(srv))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-e", "bogus"})
	err := cmd.ExecuteContext(context.Background())

	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want UsageError, got %v", err)
	}
}
