package cmd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/fieldse/osm-tools/internal/exitcode"
	"github.com/fieldse/osm-tools/internal/osmerr"
)

// atRequest is one request seen by an atServer.
type atRequest struct {
	Path  string
	Query url.Values
}

// atServer is an httptest server that records the path and query of every
// request it receives.
type atServer struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []atRequest
}

// atResponder returns the status code and body for one request.
type atResponder func(path string, q url.Values) (int, []byte)

func newATServer(t *testing.T, respond atResponder) *atServer {
	t.Helper()
	s := &atServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		s.mu.Lock()
		s.reqs = append(s.reqs, atRequest{Path: r.URL.Path, Query: q})
		s.mu.Unlock()
		status, body := respond(r.URL.Path, q)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *atServer) requests() []atRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]atRequest(nil), s.reqs...)
}

// atFixture loads a JSON response fixture from testdata/acceptance.
func atFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "acceptance", name))
	if err != nil {
		t.Fatalf("loading fixture %s: %v", name, err)
	}
	return b
}

// atAlways answers every request with the named fixture.
func atAlways(t *testing.T, fixture string) atResponder {
	body := atFixture(t, fixture)
	return func(string, url.Values) (int, []byte) { return http.StatusOK, body }
}

// atByIdentifier answers with the fixture mapped to resource_identifier, or
// the not-found fixture for any other identifier. Matching is exact and
// case-sensitive, as on the live API.
func atByIdentifier(t *testing.T, hits map[string]string) atResponder {
	notFound := atFixture(t, "check_not_found.json")
	bodies := make(map[string][]byte, len(hits))
	for id, fx := range hits {
		bodies[id] = atFixture(t, fx)
	}
	return func(_ string, q url.Values) (int, []byte) {
		if b, ok := bodies[q.Get("resource_identifier")]; ok {
			return http.StatusOK, b
		}
		return http.StatusOK, notFound
	}
}

// atOne returns the single value of a query parameter, failing if the
// parameter was sent more than once.
func atOne(t *testing.T, req atRequest, key string) string {
	t.Helper()
	if n := len(req.Query[key]); n > 1 {
		t.Fatalf("param %s sent %d times in %v", key, n, req.Query)
	}
	return req.Query.Get(key)
}

// atStatusLine returns the trimmed "status:" line of check output, failing
// unless exactly one such line exists.
func atStatusLine(t *testing.T, out string) string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(out, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "status:") {
			found = append(found, trimmed)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one status line, got %d in output:\n%s", len(found), out)
	}
	return found[0]
}

// atField returns the value of the first "<key>:" line in check output, and
// whether such a line exists.
func atField(out, key string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+":") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, key+":")), true
		}
	}
	return "", false
}

// atTokens splits s into its alphanumeric words.
func atTokens(s string) map[string]bool {
	set := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		set[f] = true
	}
	return set
}

// atWantStatus asserts the exact check status line for verdict.
func atWantStatus(t *testing.T, out, verdict string) {
	t.Helper()
	if got, want := atStatusLine(t, out), "status:      "+verdict; got != want {
		t.Errorf("status line = %q, want %q\noutput:\n%s", got, want, out)
	}
}

// atWantUsageNoRequests asserts err is a usage error (exit 2) and that the
// server saw no requests.
func atWantUsageNoRequests(t *testing.T, srv *atServer, err error) *osmerr.UsageError {
	t.Helper()
	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want *osmerr.UsageError, got %T: %v", err, err)
	}
	if code := exitcode.FromError(err); code != exitcode.Usage {
		t.Errorf("exit code = %d, want %d", code, exitcode.Usage)
	}
	if reqs := srv.requests(); len(reqs) != 0 {
		t.Errorf("want zero requests, got %d: %v", len(reqs), reqs)
	}
	return usage
}

// atPackageEcosystems is the plan's list of valid package ecosystems.
var atPackageEcosystems = []string{"npm", "pypi", "maven", "nuget", "rubygems", "packagist", "crates", "go", "vscode", "openvsx", "skills", "brew"}

// AT-1.1, AT-1.2, AT-1.3, AT-1.4, AT-1.5: an explicit -e forces a package
// lookup even when the name looks like a domain or image reference, and the
// identifier is sent unchanged. The Maven coordinate misses on the full name,
// so it alone makes a second (artifactId fallback) request.
func TestAcceptance_EcosystemFlagForcesPackageType(t *testing.T) {
	tests := []struct {
		at       string
		id       string
		eco      string
		wantReqs int
	}{
		{"AT-1.1", "smiletime.pandatask", "vscode", 1},
		{"AT-1.2", "org.mvnpm:posthog-node", "maven", 2},
		{"AT-1.3", "github.com/gobank-modules/web3-integration", "go", 1},
		{"AT-1.4", "Zendesk.OAuth", "nuget", 1},
		{"AT-1.5", "lodash.merge", "npm", 1},
	}
	for _, tt := range tests {
		t.Run(tt.at, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			_, err := runCheckCmd(t, testDeps(srv.Server), tt.id, "-e", tt.eco)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != tt.wantReqs {
				t.Fatalf("want exactly %d requests, got %d: %v", tt.wantReqs, len(reqs), reqs)
			}
			for i, r := range reqs {
				if got := atOne(t, r, "report_type"); got != "package" {
					t.Errorf("request %d report_type = %q, want package", i, got)
				}
				if got := atOne(t, r, "ecosystem"); got != tt.eco {
					t.Errorf("request %d ecosystem = %q, want %q", i, got, tt.eco)
				}
			}
			if got := atOne(t, reqs[0], "resource_identifier"); got != tt.id {
				t.Errorf("first resource_identifier = %q, want %q (unchanged)", got, tt.id)
			}
		})
	}
}

// AT-1.6: regression guard. An explicit --type domain still wins over -e.
func TestAcceptance_TypeFlagOverridesEcosystem(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_not_found.json"))
	if _, err := runCheckCmd(t, testDeps(srv.Server), "evil.com", "-e", "npm", "--type", "domain"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("want 1 request, got %d", len(reqs))
	}
	if got := atOne(t, reqs[0], "report_type"); got != "domain" {
		t.Errorf("report_type = %q, want domain", got)
	}
	if got := atOne(t, reqs[0], "resource_identifier"); got != "evil.com" {
		t.Errorf("resource_identifier = %q, want evil.com", got)
	}
}

// AT-1.7, AT-7.5: regression guard. With no -e and no --type, inference still
// maps domains, IPs and image references to their report types.
func TestAcceptance_InferenceWithoutEcosystem(t *testing.T) {
	tests := []struct {
		at   string
		id   string
		want string
	}{
		{"AT-1.7 domain", "evil.com", "domain"},
		{"AT-1.7 ip", "1.2.3.4", "ip"},
		{"AT-1.7 container", "nginx:latest", "container"},
		{"AT-7.5 container", "aquasec/trivy:0.69.5", "container"},
	}
	for _, tt := range tests {
		t.Run(tt.at, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			if _, err := runCheckCmd(t, testDeps(srv.Server), tt.id); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 1 {
				t.Fatalf("want 1 request, got %d", len(reqs))
			}
			if got := atOne(t, reqs[0], "report_type"); got != tt.want {
				t.Errorf("report_type = %q, want %q", got, tt.want)
			}
			if got := atOne(t, reqs[0], "resource_identifier"); got != tt.id {
				t.Errorf("resource_identifier = %q, want %q", got, tt.id)
			}
		})
	}
}

// AT-2.1: a hit whose version_info lists specific versions (a list or a single
// version), queried without --version, is REVIEW, and no version is sent.
func TestAcceptance_CheckHitWithoutVersionIsReview(t *testing.T) {
	tests := []struct {
		fixture, id, eco string
	}{
		{"check_hit_no_version.json", "axios", "npm"},
		{"check_hit_single_version.json", "tns-py", "pypi"},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, tt.fixture))
			out, err := runCheckCmd(t, testDeps(srv.Server), tt.id, "-e", tt.eco)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			atWantStatus(t, out, "REVIEW")
			reqs := srv.requests()
			if len(reqs) != 1 {
				t.Fatalf("want 1 request, got %d", len(reqs))
			}
			if got := atOne(t, reqs[0], "version"); got != "" {
				t.Errorf("version = %q, want none", got)
			}
		})
	}
}

// AT-2.1, AT-2.2: a --version that is a range is not an exact version, so a
// hit listing specific versions stays REVIEW rather than MALICIOUS.
func TestAcceptance_CheckRangeVersionIsNotExact(t *testing.T) {
	for _, v := range []string{"^1.14.0", "~1.14.0", ">=1.0.0", "1.x", "*"} {
		t.Run(v, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_hit_no_version.json"))
			out, err := runCheckCmd(t, testDeps(srv.Server), "axios", "-e", "npm", "--version", v)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			atWantStatus(t, out, "REVIEW")
		})
	}
}

// AT-2.2: regression guard. The same hit queried with an exact listed
// --version is MALICIOUS, and that version is sent.
func TestAcceptance_CheckHitWithExactVersionIsMalicious(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_hit_exact_version.json"))
	out, err := runCheckCmd(t, testDeps(srv.Server), "axios", "-e", "npm", "--version", "1.14.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	atWantStatus(t, out, "MALICIOUS")
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("want 1 request, got %d", len(reqs))
	}
	if got := atOne(t, reqs[0], "version"); got != "1.14.1" {
		t.Errorf("version = %q, want 1.14.1", got)
	}
}

// AT-2.3: regression guard. A hit whose version_info is "all", null or blank
// is MALICIOUS even without --version.
func TestAcceptance_CheckAllVersionsHitIsMalicious(t *testing.T) {
	for _, fx := range []string{
		"check_hit_version_info_all.json",
		"check_hit_version_info_null.json",
		"check_hit_version_info_blank.json",
	} {
		t.Run(fx, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, fx))
			out, err := runCheckCmd(t, testDeps(srv.Server), "evil-pkg", "-e", "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			atWantStatus(t, out, "MALICIOUS")
		})
	}
}

// AT-2.4: malicious:false with a warning and known_malicious_versions is
// REVIEW, and the known versions are printed.
func TestAcceptance_CheckWarningIsReview(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_version_miss_warning.json"))
	out, err := runCheckCmd(t, testDeps(srv.Server), "axios", "-e", "npm", "--version", "1.99.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	atWantStatus(t, out, "REVIEW")
	for _, v := range []string{"1.14.1", "0.30.4"} {
		if !strings.Contains(out, v) {
			t.Errorf("output missing known malicious version %s:\n%s", v, out)
		}
	}
}

// AT-2.4: either a non-empty warning alone or non-empty
// known_malicious_versions alone makes a malicious:false response REVIEW, and
// known versions are printed.
func TestAcceptance_CheckWarningFieldsEachTriggerReview(t *testing.T) {
	tests := []struct {
		fixture, id string
		wantInOut   []string
	}{
		{"check_warning_only.json", "warn-only-pkg", nil},
		{"check_known_versions_only.json", "known-only-pkg", []string{"3.0.0", "3.0.2"}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, tt.fixture))
			out, err := runCheckCmd(t, testDeps(srv.Server), tt.id, "-e", "npm", "--version", "9.9.9")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			atWantStatus(t, out, "REVIEW")
			for _, v := range tt.wantInOut {
				if !strings.Contains(out, v) {
					t.Errorf("output missing known malicious version %s:\n%s", v, out)
				}
			}
		})
	}
}

// AT-2.4, AT-2.5: regression guard. An empty warning and an empty
// known_malicious_versions list do not make a response REVIEW; it stays CLEAN.
func TestAcceptance_CheckEmptyWarningIsClean(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_empty_warning.json"))
	out, err := runCheckCmd(t, testDeps(srv.Server), "plain-pkg", "-e", "npm", "--version", "9.9.9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	atWantStatus(t, out, "CLEAN")
}

// AT-2.5: regression guard. A not-found response is CLEAN.
func TestAcceptance_CheckNotFoundIsClean(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_not_found.json"))
	out, err := runCheckCmd(t, testDeps(srv.Server), "left-pad", "-e", "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	atWantStatus(t, out, "CLEAN")
}

// AT-2.6: check prints each of MALICIOUS, REVIEW and CLEAN and exits 0 for all
// three.
func TestAcceptance_CheckExitsZeroForEveryVerdict(t *testing.T) {
	tests := []struct {
		fixture string
		verdict string
	}{
		{"check_hit_version_info_all.json", "MALICIOUS"},
		{"check_hit_no_version.json", "REVIEW"},
		{"check_not_found.json", "CLEAN"},
	}
	for _, tt := range tests {
		t.Run(tt.verdict, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, tt.fixture))
			out, err := runCheckCmd(t, testDeps(srv.Server), "some-pkg", "-e", "npm")
			if code := exitcode.FromError(err); code != exitcode.OK {
				t.Fatalf("exit code = %d (err %v), want 0", code, err)
			}
			atWantStatus(t, out, tt.verdict)
		})
	}
}

// AT-4.1, AT-4.2: check prints a versions: line with version_info and a url:
// line with osm_url. The second case's osm_url cannot be built from the
// ecosystem and name, so the url must come from the response.
func TestAcceptance_CheckShowsVersionsAndURL(t *testing.T) {
	tests := []struct {
		fixture, id, eco, wantVersions, wantURL string
	}{
		{"check_hit_no_version.json", "axios", "npm", "1.14.1, 0.30.4", "https://opensourcemalware.com/npm/axios"},
		{"check_hit_single_version.json", "tns-py", "pypi", "2.0.1", "https://opensourcemalware.com/threat/7f3c9e21-4b8a-4d6e-a1f0-3c5b7d9e2a64"},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, tt.fixture))
			out, err := runCheckCmd(t, testDeps(srv.Server), tt.id, "-e", tt.eco)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v, ok := atField(out, "versions"); !ok || !strings.Contains(v, tt.wantVersions) {
				t.Errorf("AT-4.1: want versions: line with %q, got %q (present=%v)\n%s", tt.wantVersions, v, ok, out)
			}
			if v, ok := atField(out, "url"); !ok || v != tt.wantURL {
				t.Errorf("AT-4.2: want url: line %q, got %q (present=%v)\n%s", tt.wantURL, v, ok, out)
			}
		})
	}
}

// AT-8.1: the hit-with-exact-version fixture decodes and check prints its
// verdict, severity, versions and url.
func TestAcceptance_CheckDecodesExactVersionHit(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_hit_exact_version.json"))
	out, err := runCheckCmd(t, testDeps(srv.Server), "axios", "-e", "npm", "--version", "1.14.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	atWantStatus(t, out, "MALICIOUS")
	if v, _ := atField(out, "severity"); v != "critical" {
		t.Errorf("severity = %q, want critical\n%s", v, out)
	}
	if v, ok := atField(out, "versions"); !ok || !strings.Contains(v, "1.14.1, 0.30.4") {
		t.Errorf("versions = %q (present=%v), want it to contain 1.14.1, 0.30.4\n%s", v, ok, out)
	}
	if v, ok := atField(out, "url"); !ok || v != "https://opensourcemalware.com/npm/axios" {
		t.Errorf("url = %q (present=%v), want osm_url\n%s", v, ok, out)
	}
}

// AT-6.1: an unknown -e is a usage error and sends nothing.
func TestAcceptance_CheckRejectsUnknownEcosystem(t *testing.T) {
	for _, eco := range []string{"cargo", "pip", "golang"} {
		t.Run(eco, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			_, err := runCheckCmd(t, testDeps(srv.Server), "x", "-e", eco)
			atWantUsageNoRequests(t, srv, err)
		})
	}
}

// AT-6.2: -e is lowercased before validation and sent lowercased; the
// identifier keeps its case.
func TestAcceptance_CheckLowercasesEcosystem(t *testing.T) {
	tests := []struct {
		id, eco, want string
	}{
		{"tns-py", "PyPI", "pypi"},
		{"left-pad", "NPM", "npm"},
		{"Newtonsoft.Json", "NuGet", "nuget"},
	}
	for _, tt := range tests {
		t.Run(tt.eco, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			if _, err := runCheckCmd(t, testDeps(srv.Server), tt.id, "-e", tt.eco); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 1 {
				t.Fatalf("want 1 request, got %d", len(reqs))
			}
			if got := atOne(t, reqs[0], "ecosystem"); got != tt.want {
				t.Errorf("ecosystem = %q, want %q", got, tt.want)
			}
			if got := atOne(t, reqs[0], "resource_identifier"); got != tt.id {
				t.Errorf("resource_identifier = %q, want %q", got, tt.id)
			}
		})
	}
}

// AT-6.3: the unknown-ecosystem usage message lists every valid ecosystem.
func TestAcceptance_CheckEcosystemUsageListsValid(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_not_found.json"))
	_, err := runCheckCmd(t, testDeps(srv.Server), "x", "-e", "cargo")
	usage := atWantUsageNoRequests(t, srv, err)
	words := atTokens(usage.Error())
	for _, eco := range atPackageEcosystems {
		if !words[eco] {
			t.Errorf("usage message does not list %q: %s", eco, usage.Error())
		}
	}
}

// AT-7.1, AT-7.2, AT-7.3: repository URLs, other URLs and wallet addresses are
// rejected as not supported before any request is sent.
func TestAcceptance_CheckRejectsUnsupportedAssets(t *testing.T) {
	tests := []struct {
		at string
		id string
	}{
		{"AT-7.1 github repo", "https://github.com/Owner/repo"},
		{"AT-7.1 gitlab repo", "https://gitlab.com/group/project"},
		{"AT-7.2 http url", "http://example.com/payload"},
		{"AT-7.2 https url", "https://evil.example/stage2.sh"},
		{"AT-7.3 wallet", "0x1234567890abcdef1234567890abcdef12345678"},
		{"AT-7.3 checksummed wallet", "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"},
	}
	for _, tt := range tests {
		t.Run(tt.at, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			_, err := runCheckCmd(t, testDeps(srv.Server), tt.id)
			usage := atWantUsageNoRequests(t, srv, err)
			if !strings.Contains(strings.ToLower(usage.Error()), "not supported") {
				t.Errorf("usage message does not say %q: %s", "not supported", usage.Error())
			}
		})
	}
}

// AT-7.4: regression guard. --type repository, url and wallet are usage errors
// and send nothing.
func TestAcceptance_CheckRejectsUnsupportedTypeFlags(t *testing.T) {
	tests := []struct {
		typ string
		id  string
	}{
		{"repository", "github.com/owner/repo"},
		{"url", "example.com/payload"},
		{"wallet", "0x1234567890abcdef1234567890abcdef12345678"},
	}
	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			_, err := runCheckCmd(t, testDeps(srv.Server), tt.id, "--type", tt.typ)
			atWantUsageNoRequests(t, srv, err)
		})
	}
}

// AT-9.1: a Maven groupId:artifactId that is not found falls back to the bare
// artifactId. Exactly two requests, full name first; the fallback-only hit is
// REVIEW even when version_info is "all", and the output names the fallback.
func TestAcceptance_MavenArtifactFallback(t *testing.T) {
	tests := []struct {
		full, artifact string
	}{
		{"io.github.xz-java:xz-java", "xz-java"},
		{"com.example.evil:stealer-lib", "stealer-lib"},
	}
	for _, tt := range tests {
		t.Run(tt.full, func(t *testing.T) {
			srv := newATServer(t, atByIdentifier(t, map[string]string{tt.artifact: "check_hit_version_info_all.json"}))
			out, err := runCheckCmd(t, testDeps(srv.Server), tt.full, "-e", "maven")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 2 {
				t.Fatalf("want exactly 2 requests, got %d: %v", len(reqs), reqs)
			}
			for i, want := range []string{tt.full, tt.artifact} {
				if got := atOne(t, reqs[i], "resource_identifier"); got != want {
					t.Errorf("request %d resource_identifier = %q, want %q", i, got, want)
				}
				if got := atOne(t, reqs[i], "report_type"); got != "package" {
					t.Errorf("request %d report_type = %q, want package", i, got)
				}
				if got := atOne(t, reqs[i], "ecosystem"); got != "maven" {
					t.Errorf("request %d ecosystem = %q, want maven", i, got)
				}
			}
			atWantStatus(t, out, "REVIEW")
			if !strings.Contains(strings.ToLower(out), "artifactid") {
				t.Errorf("output does not name the artifactId fallback:\n%s", out)
			}
		})
	}
}

// AT-9.1 (hostile input): query syntax in a Maven coordinate reaches the
// fallback request only as an encoded identifier and cannot add or override
// report_type or ecosystem params.
func TestAcceptance_MavenFallbackEncodesIdentifier(t *testing.T) {
	const artifact = "lib&ecosystem=npm&report_type=domain#frag"
	full := "com.evil:" + artifact
	srv := newATServer(t, atAlways(t, "check_not_found.json"))
	if _, err := runCheckCmd(t, testDeps(srv.Server), full, "-e", "maven"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := srv.requests()
	if len(reqs) != 2 {
		t.Fatalf("want exactly 2 requests, got %d: %v", len(reqs), reqs)
	}
	for i, want := range []string{full, artifact} {
		if got := atOne(t, reqs[i], "resource_identifier"); got != want {
			t.Errorf("request %d resource_identifier = %q, want %q", i, got, want)
		}
		if got := atOne(t, reqs[i], "ecosystem"); got != "maven" {
			t.Errorf("request %d ecosystem = %q, want maven", i, got)
		}
		if got := atOne(t, reqs[i], "report_type"); got != "package" {
			t.Errorf("request %d report_type = %q, want package", i, got)
		}
	}
}

// AT-9.1: when the full Maven name and the bare artifactId both miss, check
// sends exactly two requests (full, then artifact) and the verdict is CLEAN.
func TestAcceptance_MavenFallbackMissIsClean(t *testing.T) {
	tests := []struct {
		full, artifact string
	}{
		{"org.example.safe:util-core", "util-core"},
		{"net.sample:widget", "widget"},
	}
	for _, tt := range tests {
		t.Run(tt.full, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			out, err := runCheckCmd(t, testDeps(srv.Server), tt.full, "-e", "maven")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 2 {
				t.Fatalf("want exactly 2 requests, got %d: %v", len(reqs), reqs)
			}
			for i, want := range []string{tt.full, tt.artifact} {
				if got := atOne(t, reqs[i], "resource_identifier"); got != want {
					t.Errorf("request %d resource_identifier = %q, want %q", i, got, want)
				}
			}
			atWantStatus(t, out, "CLEAN")
		})
	}
}

// AT-9.2, AT-1.2: a hit on the full Maven name sends exactly one request and
// follows the normal verdict rules (version_info "all" is MALICIOUS; listed
// versions with no --version is REVIEW).
func TestAcceptance_MavenFullNameHitNoFallback(t *testing.T) {
	tests := []struct {
		full, fixture, verdict string
	}{
		{"org.mvnpm:posthog-node", "check_hit_version_info_all.json", "MALICIOUS"},
		{"com.acme.telemetry:tracker-sdk", "check_hit_no_version.json", "REVIEW"},
	}
	for _, tt := range tests {
		t.Run(tt.full, func(t *testing.T) {
			srv := newATServer(t, atByIdentifier(t, map[string]string{tt.full: tt.fixture}))
			out, err := runCheckCmd(t, testDeps(srv.Server), tt.full, "-e", "maven")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 1 {
				t.Fatalf("want exactly 1 request, got %d: %v", len(reqs), reqs)
			}
			if got := atOne(t, reqs[0], "report_type"); got != "package" {
				t.Errorf("report_type = %q, want package", got)
			}
			if got := atOne(t, reqs[0], "resource_identifier"); got != tt.full {
				t.Errorf("resource_identifier = %q, want %q", got, tt.full)
			}
			atWantStatus(t, out, tt.verdict)
		})
	}
}

// AT-9.3: regression guard. A Maven name with no colon sends exactly one
// request.
func TestAcceptance_MavenBareArtifactSingleRequest(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_not_found.json"))
	out, err := runCheckCmd(t, testDeps(srv.Server), "xz-java", "-e", "maven")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("want exactly 1 request, got %d: %v", len(reqs), reqs)
	}
	if got := atOne(t, reqs[0], "resource_identifier"); got != "xz-java" {
		t.Errorf("resource_identifier = %q, want xz-java", got)
	}
	atWantStatus(t, out, "CLEAN")
}

// AT-9.4, AT-8.2: a warning-shape response (details:null) on the full Maven
// name is REVIEW with no fallback request.
func TestAcceptance_MavenWarningNoFallback(t *testing.T) {
	const full = "io.github.xz-java:xz-java"
	srv := newATServer(t, atByIdentifier(t, map[string]string{full: "check_version_miss_warning.json"}))
	out, err := runCheckCmd(t, testDeps(srv.Server), full, "-e", "maven")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("want exactly 1 request, got %d: %v", len(reqs), reqs)
	}
	if got := atOne(t, reqs[0], "resource_identifier"); got != full {
		t.Errorf("resource_identifier = %q, want %q", got, full)
	}
	atWantStatus(t, out, "REVIEW")
}

// AT-10.1, AT-10.2: domain identifiers are lowercased and a trailing dot is
// stripped before sending, whether inferred or set with --type domain.
func TestAcceptance_DomainNormalised(t *testing.T) {
	tests := []struct {
		at   string
		args []string
		want string
	}{
		{"AT-10.1 mixed case", []string{"Server-Genimi-Check.Vercel.App"}, "server-genimi-check.vercel.app"},
		{"AT-10.1 upper case", []string{"EVIL.COM"}, "evil.com"},
		{"AT-10.1 explicit type", []string{"Evil.Example.Net", "--type", "domain"}, "evil.example.net"},
		{"AT-10.2 trailing dot", []string{"evil.com."}, "evil.com"},
		{"AT-10.2 trailing dot mixed case", []string{"Mixed.Example.ORG."}, "mixed.example.org"},
	}
	for _, tt := range tests {
		t.Run(tt.at, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			if _, err := runCheckCmd(t, testDeps(srv.Server), tt.args...); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 1 {
				t.Fatalf("want 1 request, got %d", len(reqs))
			}
			if got := atOne(t, reqs[0], "report_type"); got != "domain" {
				t.Errorf("report_type = %q, want domain", got)
			}
			if got := atOne(t, reqs[0], "resource_identifier"); got != tt.want {
				t.Errorf("resource_identifier = %q, want %q", got, tt.want)
			}
		})
	}
}

// AT-10.3: regression guard. Package identifiers keep their case.
func TestAcceptance_PackageIdentifierCaseKept(t *testing.T) {
	tests := []struct {
		id, eco string
	}{
		{"Zendesk.OAuth", "nuget"},
		{"Microsoft.Extensions.Logging", "nuget"},
		{"PyYAML", "pypi"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			if _, err := runCheckCmd(t, testDeps(srv.Server), tt.id, "-e", tt.eco); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 1 {
				t.Fatalf("want 1 request, got %d", len(reqs))
			}
			if got := atOne(t, reqs[0], "resource_identifier"); got != tt.id {
				t.Errorf("resource_identifier = %q, want %q", got, tt.id)
			}
		})
	}
}
