package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
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
		w.Write([]byte(`{"malicious":true,"details":{"severity_level":"high","description":"bad"}}`))
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
		{"ecosystem forces package", "lodash.merge", "", "npm", infer.TypePackage, false},
		{"type wins over ecosystem", "evil.com", "domain", "npm", infer.TypeDomain, false},
		{"url rejected", "https://example.com/x", "", "", "", true},
		{"url rejected as domain", "https://example.com/x", "domain", "", "", true},
		{"wallet type rejected", "x", "wallet", "", "", true},
		{"repo path rejected", "github.com/gobank-modules/web3-integration", "", "", "", true},
		{"scp repo rejected", "git@github.com:owner/repo.git", "", "", "", true},
		{"ssh url rejected", "ssh://git@github.com/o/r", "", "", "", true},
		{"ftp url rejected", "ftp://evil.com/x", "", "", "", true},
		{"repo path with ecosystem is a package", "github.com/gobank-modules/web3-integration", "", "go", infer.TypePackage, false},
		{"untagged private image with --type docker", "registry.example.com/team/image", "docker", "", infer.TypeDocker, false},
		{"tagged private image inferred", "registry.example.com/team/image:1.0", "", "", infer.TypeDocker, false},
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

func TestCheckEcosystem(t *testing.T) {
	if got, err := checkEcosystem(" PyPI "); err != nil || got != "pypi" {
		t.Errorf("checkEcosystem(PyPI) = %q, %v; want pypi, nil", got, err)
	}
	if got, err := checkEcosystem(""); err != nil || got != "" {
		t.Errorf("checkEcosystem(\"\") = %q, %v; want empty, nil", got, err)
	}
	var usage *osmerr.UsageError
	if _, err := checkEcosystem("cargo"); !errors.As(err, &usage) {
		t.Errorf("checkEcosystem(cargo) err = %v, want UsageError", err)
	}
}

func TestParseMavenCoord(t *testing.T) {
	maven := func(id string) client.Query {
		return client.Query{Type: "package", Ecosystem: "maven", Identifier: id}
	}
	tests := []struct {
		q      client.Query
		want   mavenCoord
		wantOK bool
	}{
		{maven("org.example:lib"), mavenCoord{"org.example:lib", "lib", ""}, true},
		{maven("a:b:c"), mavenCoord{"a:b", "b", "c"}, true},
		{maven("org.example:evil-lib:1.2.3"), mavenCoord{"org.example:evil-lib", "evil-lib", "1.2.3"}, true},
		{maven("org.example:evil-lib:jar:1.2.3"), mavenCoord{"org.example:evil-lib", "evil-lib", "1.2.3"}, true},
		{maven("org.example:evil-lib:jar:sources:1.2.3"), mavenCoord{"org.example:evil-lib", "evil-lib", "1.2.3"}, true},
		{maven("lib"), mavenCoord{}, false},
		{maven("org.example:"), mavenCoord{}, false},
		{maven("org.example::1.0"), mavenCoord{}, false},
		{client.Query{Type: "package", Ecosystem: "npm", Identifier: "a:b"}, mavenCoord{}, false},
	}
	for _, tt := range tests {
		got, ok := parseMavenCoord(tt.q)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("parseMavenCoord(%q) = %+v, %v; want %+v, %v", tt.q.Identifier, got, ok, tt.want, tt.wantOK)
		}
	}
}

// mavenServer answers check-malicious from records keyed by identifier and
// logs each request's identifier and version.
func mavenServer(t *testing.T, records map[string]string) (*httptest.Server, *[][2]string) {
	t.Helper()
	var mu sync.Mutex
	var reqs [][2]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, v := r.URL.Query().Get("resource_identifier"), r.URL.Query().Get("version")
		mu.Lock()
		reqs = append(reqs, [2]string{id, v})
		mu.Unlock()
		if body, ok := records[id]; ok {
			w.Write([]byte(body))
			return
		}
		w.Write([]byte(`{"malicious":false}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func TestCheckCmd_MavenGAVFallback(t *testing.T) {
	const listed = `{"malicious":true,"details":{"severity_level":"high","version_info":"1.2.3, 1.2.4"}}`
	tests := []struct {
		name    string
		args    []string
		records map[string]string
		want    [][2]string
		verdict string
	}{
		{
			name:    "GAV hit on groupId:artifactId uses the coordinate version",
			args:    []string{"org.example:evil-lib:1.2.3"},
			records: map[string]string{"org.example:evil-lib": listed},
			want:    [][2]string{{"org.example:evil-lib:1.2.3", ""}, {"org.example:evil-lib", "1.2.3"}},
			verdict: "MALICIOUS",
		},
		{
			name:    "GAV with packaging hit on bare artifactId",
			args:    []string{"org.example:evil-lib:jar:1.2.3"},
			records: map[string]string{"evil-lib": listed},
			want: [][2]string{
				{"org.example:evil-lib:jar:1.2.3", ""},
				{"org.example:evil-lib", "1.2.3"},
				{"evil-lib", "1.2.3"},
			},
			verdict: "REVIEW",
		},
		{
			name:    "--version overrides the coordinate version",
			args:    []string{"org.example:evil-lib:1.2.3", "--version", "9.9.9"},
			records: map[string]string{},
			want: [][2]string{
				{"org.example:evil-lib:1.2.3", "9.9.9"},
				{"org.example:evil-lib", "9.9.9"},
				{"evil-lib", "9.9.9"},
			},
			verdict: "CLEAN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, reqs := mavenServer(t, tt.records)
			out, err := runCheckCmd(t, testDeps(srv), append(tt.args, "-e", "maven")...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(*reqs, tt.want) {
				t.Errorf("requests = %v, want %v", *reqs, tt.want)
			}
			if !strings.Contains(out, tt.verdict) {
				t.Errorf("want verdict %s in output:\n%s", tt.verdict, out)
			}
		})
	}
}
