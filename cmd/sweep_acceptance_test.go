package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/exitcode"
	"github.com/fieldse/osm-tools/internal/osmerr"
)

// atAxiosModel answers check-malicious the way the live API does for axios,
// whose malicious versions are 1.14.1 and 0.30.4: no version → hit with
// "version":null; a listed version → hit; any other version string (including
// a range) → malicious:false with a warning. Every other name is not found.
func atAxiosModel(t *testing.T) atResponder {
	noVersion := atFixture(t, "check_hit_no_version.json")
	exact := atFixture(t, "check_hit_exact_version.json")
	warning := atFixture(t, "check_version_miss_warning.json")
	notFound := atFixture(t, "check_not_found.json")
	return func(_ string, q url.Values) (int, []byte) {
		if q.Get("resource_identifier") != "axios" {
			return http.StatusOK, notFound
		}
		switch q.Get("version") {
		case "":
			return http.StatusOK, noVersion
		case "1.14.1", "0.30.4":
			return http.StatusOK, exact
		default:
			return http.StatusOK, warning
		}
	}
}

// atSweepJSON runs sweep -o json and decodes the rows into generic maps.
func atSweepJSON(t *testing.T, deps *appDeps, manifest string, extra ...string) ([]map[string]any, error) {
	t.Helper()
	out, err := runSweepCmd(t, deps, append([]string{"-f", manifest, "-o", "json"}, extra...)...)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if jerr := json.Unmarshal([]byte(out), &rows); jerr != nil {
		t.Fatalf("sweep JSON output is not an array of objects: %v\n%s", jerr, out)
	}
	return rows, nil
}

// atRow returns the JSON row for pkg, failing if it is absent.
func atRow(t *testing.T, rows []map[string]any, pkg string) map[string]any {
	t.Helper()
	for _, r := range rows {
		if r["package"] == pkg {
			return r
		}
	}
	t.Fatalf("no row for package %q in %v", pkg, rows)
	return nil
}

// atRequestsFor returns the recorded requests whose resource_identifier is id.
func atRequestsFor(srv *atServer, id string) []atRequest {
	var out []atRequest
	for _, r := range srv.requests() {
		if r.Query.Get("resource_identifier") == id {
			out = append(out, r)
		}
	}
	return out
}

// AT-2.7: a sweep JSON row for a version-miss warning has "status":"REVIEW";
// a clean dependency in the same sweep does not.
func TestAcceptance_SweepJSONReviewRow(t *testing.T) {
	srv := newATServer(t, atAxiosModel(t))
	manifest := writeManifest(t, map[string]string{"axios": "1.99.0", "left-pad": "1.3.0"})
	rows, err := atSweepJSON(t, sweepDeps(t, srv.Server), manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := atRow(t, rows, "axios")["status"]; got != "REVIEW" {
		t.Errorf("axios status = %v, want REVIEW", got)
	}
	if got := atRow(t, rows, "left-pad")["status"]; got == "REVIEW" || got == "MALICIOUS" {
		t.Errorf("left-pad status = %v, want a clean verdict", got)
	}
}

// AT-2.8: sweep --fail-on-any with only a REVIEW row trips the gate (exit 3),
// whether the REVIEW comes from a version-miss warning or from a range spec
// whose no-version hit lists specific versions.
func TestAcceptance_SweepFailOnAnyReviewTripsGate(t *testing.T) {
	tests := []struct {
		name string
		deps map[string]string
	}{
		{"warning", map[string]string{"axios": "1.99.0", "left-pad": "1.3.0"}},
		{"range hit", map[string]string{"axios": "^1.14.0", "left-pad": "1.3.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newATServer(t, atAxiosModel(t))
			manifest := writeManifest(t, tt.deps)
			_, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", manifest, "--fail-on-any")
			var gate *osmerr.GateTriggered
			if !errors.As(err, &gate) {
				t.Fatalf("want *osmerr.GateTriggered, got %T: %v", err, err)
			}
			if code := exitcode.FromError(err); code != exitcode.Gate {
				t.Errorf("exit code = %d, want %d", code, exitcode.Gate)
			}
			if len(gate.Hits) != 1 || !strings.Contains(gate.Hits[0], "axios") {
				t.Errorf("gate hits = %v, want one entry naming axios", gate.Hits)
			}
		})
	}
}

// AT-2.9: regression guard. sweep --fail-on-any with only clean rows returns
// nil (exit 0).
func TestAcceptance_SweepFailOnAnyCleanPasses(t *testing.T) {
	srv := newATServer(t, atAxiosModel(t))
	manifest := writeManifest(t, map[string]string{"left-pad": "1.3.0", "express": "4.18.2"})
	_, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", manifest, "--fail-on-any")
	if err != nil {
		t.Fatalf("want nil, got %T: %v", err, err)
	}
	if code := exitcode.FromError(err); code != exitcode.OK {
		t.Errorf("exit code = %d, want 0", code)
	}
	if n := len(srv.requests()); n != 2 {
		t.Errorf("want 2 requests, got %d", n)
	}
}

// AT-2.10: the sweep table shows REVIEW in the row for a REVIEW dependency.
func TestAcceptance_SweepTableReviewRow(t *testing.T) {
	srv := newATServer(t, atAxiosModel(t))
	manifest := writeManifest(t, map[string]string{"axios": "1.99.0", "left-pad": "1.3.0"})
	out, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rowFields := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			rowFields[f[0]] = f
		}
	}
	has := func(fields []string, s string) bool {
		for _, f := range fields {
			if f == s {
				return true
			}
		}
		return false
	}
	if f, ok := rowFields["axios"]; !ok || !has(f, "REVIEW") {
		t.Errorf("axios row = %v, want a REVIEW column\n%s", f, out)
	}
	if f := rowFields["left-pad"]; has(f, "REVIEW") {
		t.Errorf("left-pad row = %v, want no REVIEW\n%s", f, out)
	}
}

// AT-3.1, AT-3.5: package.json "axios":"^1.14.0" sends no version, and the
// resulting hit with specific versions is a REVIEW row, not clean.
func TestAcceptance_SweepRangeSendsNoVersionAndIsReview(t *testing.T) {
	srv := newATServer(t, atAxiosModel(t))
	manifest := writeManifest(t, map[string]string{"axios": "^1.14.0"})
	rows, err := atSweepJSON(t, sweepDeps(t, srv.Server), manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("want exactly 1 request, got %d: %v", len(reqs), reqs)
	}
	r := reqs[0]
	if got := atOne(t, r, "version"); got != "" {
		t.Errorf("AT-3.1: version = %q, want none", got)
	}
	if got := atOne(t, r, "resource_identifier"); got != "axios" {
		t.Errorf("resource_identifier = %q, want axios", got)
	}
	if got := atOne(t, r, "ecosystem"); got != "npm" {
		t.Errorf("ecosystem = %q, want npm", got)
	}
	if got := atOne(t, r, "report_type"); got != "package" {
		t.Errorf("report_type = %q, want package", got)
	}
	if got := atRow(t, rows, "axios")["status"]; got != "REVIEW" {
		t.Errorf("AT-3.5: axios status = %v, want REVIEW", got)
	}
}

// AT-3.2: range and non-registry specs send no version. Registry ranges are
// still looked up exactly once; non-registry specs (workspace, file, git,
// tarball URL) are looked up at most once.
func TestAcceptance_SweepRangeSpecsSendNoVersion(t *testing.T) {
	tests := []struct {
		spec     string
		registry bool
	}{
		{"~1.2.3", true},
		{">=1.0.0", true},
		{"1.x", true},
		{"*", true},
		{"latest", true},
		{"1.2.3 - 2.0.0", true},
		{"^1 || ^2", true},
		{"workspace:*", false},
		{"file:../x", false},
		{"git+https://github.com/owner/some-dep.git#v1.2.3", false},
		{"https://registry.example.com/some-dep/-/some-dep-1.2.3.tgz", false},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			manifest := writeManifest(t, map[string]string{"some-dep": tt.spec})
			if _, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", manifest); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := atRequestsFor(srv, "some-dep")
			if tt.registry && len(reqs) != 1 {
				t.Fatalf("want exactly 1 request for some-dep, got %d: %v", len(reqs), srv.requests())
			}
			if len(reqs) > 1 {
				t.Fatalf("want at most 1 request for some-dep, got %d", len(reqs))
			}
			for _, r := range reqs {
				if got := atOne(t, r, "version"); got != "" {
					t.Errorf("version = %q, want none for spec %q", got, tt.spec)
				}
			}
		})
	}
}

// AT-3.3: regression guard. Exact versions, including prereleases, are sent
// verbatim.
func TestAcceptance_SweepExactVersionsSent(t *testing.T) {
	for _, v := range []string{"1.2.3", "1.2.3-beta.1"} {
		t.Run(v, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			manifest := writeManifest(t, map[string]string{"some-dep": v})
			if _, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", manifest); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 1 {
				t.Fatalf("want 1 request, got %d", len(reqs))
			}
			if got := atOne(t, reqs[0], "version"); got != v {
				t.Errorf("version = %q, want %q", got, v)
			}
		})
	}
}

// AT-3.3: an "=" spec is an exact version and is sent without the "=".
func TestAcceptance_SweepEqualsPrefixStripped(t *testing.T) {
	tests := []struct{ spec, want string }{
		{"=1.2.3", "1.2.3"},
		{"=10.0.0-beta.2", "10.0.0-beta.2"},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			manifest := writeManifest(t, map[string]string{"some-dep": tt.spec})
			if _, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", manifest); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 1 {
				t.Fatalf("want 1 request, got %d", len(reqs))
			}
			if got := atOne(t, reqs[0], "version"); got != tt.want {
				t.Errorf("version = %q, want %q", got, tt.want)
			}
		})
	}
}

// AT-3.4: an npm alias "name":"npm:target@spec" is looked up as the target
// package, with the range rules applied to its spec.
func TestAcceptance_SweepNpmAliasResolved(t *testing.T) {
	tests := []struct {
		alias, spec, wantID, wantVersion string
	}{
		{"my-axios", "npm:axios@1.14.1", "axios", "1.14.1"},
		{"my-babel", "npm:@babel/core@7.24.0", "@babel/core", "7.24.0"},
		{"loose-axios", "npm:axios@^1.14.0", "axios", ""},
	}
	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			srv := newATServer(t, atAlways(t, "check_not_found.json"))
			manifest := writeManifest(t, map[string]string{tt.alias: tt.spec})
			if _, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", manifest); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reqs := srv.requests()
			if len(reqs) != 1 {
				t.Fatalf("want exactly 1 request, got %d: %v", len(reqs), reqs)
			}
			if got := atOne(t, reqs[0], "resource_identifier"); got != tt.wantID {
				t.Errorf("resource_identifier = %q, want %q", got, tt.wantID)
			}
			if got := atOne(t, reqs[0], "version"); got != tt.wantVersion {
				t.Errorf("version = %q, want %q", got, tt.wantVersion)
			}
		})
	}
}

// AT-4.3: sweep JSON rows carry affected_versions (from version_info) and
// osm_url.
func TestAcceptance_SweepJSONAffectedVersionsAndURL(t *testing.T) {
	srv := newATServer(t, atAxiosModel(t))
	manifest := writeManifest(t, map[string]string{"axios": "1.14.1"})
	rows, err := atSweepJSON(t, sweepDeps(t, srv.Server), manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	row := atRow(t, rows, "axios")
	if row["status"] != "MALICIOUS" {
		t.Errorf("status = %v, want MALICIOUS", row["status"])
	}
	affected, ok := row["affected_versions"]
	if !ok {
		t.Fatalf("row has no affected_versions key: %v", row)
	}
	for _, v := range []string{"1.14.1", "0.30.4"} {
		if !strings.Contains(fmt.Sprint(affected), v) {
			t.Errorf("affected_versions = %v, want it to contain %s", affected, v)
		}
	}
	if got := row["osm_url"]; got != "https://opensourcemalware.com/npm/axios" {
		t.Errorf("osm_url = %v, want https://opensourcemalware.com/npm/axios", got)
	}
}

// AT-4.3: affected_versions and osm_url come from each row's own response. The
// evil-sdk osm_url cannot be built from the package name, and the clean row
// does not inherit another row's url.
func TestAcceptance_SweepJSONRowFieldsFromOwnResponse(t *testing.T) {
	single := atFixture(t, "check_hit_single_version.json")
	axios := atAxiosModel(t)
	srv := newATServer(t, func(path string, q url.Values) (int, []byte) {
		if q.Get("resource_identifier") == "evil-sdk" {
			return http.StatusOK, single
		}
		return axios(path, q)
	})
	manifest := writeManifest(t, map[string]string{"axios": "1.14.1", "evil-sdk": "2.0.1", "left-pad": "1.3.0"})
	rows, err := atSweepJSON(t, sweepDeps(t, srv.Server), manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	evil := atRow(t, rows, "evil-sdk")
	if evil["status"] != "MALICIOUS" {
		t.Errorf("evil-sdk status = %v, want MALICIOUS", evil["status"])
	}
	affected, ok := evil["affected_versions"]
	if !ok || !strings.Contains(fmt.Sprint(affected), "2.0.1") || strings.Contains(fmt.Sprint(affected), "1.14.1") {
		t.Errorf("evil-sdk affected_versions = %v (present=%v), want its own 2.0.1", affected, ok)
	}
	if got, want := evil["osm_url"], "https://opensourcemalware.com/threat/7f3c9e21-4b8a-4d6e-a1f0-3c5b7d9e2a64"; got != want {
		t.Errorf("evil-sdk osm_url = %v, want %s", got, want)
	}
	if got, ok := atRow(t, rows, "left-pad")["osm_url"]; ok && got != "" {
		t.Errorf("left-pad osm_url = %v, want absent or empty", got)
	}
}

// AT-8.3: the sweep table has no FIRST_SEEN column and JSON rows have no
// first_seen key.
func TestAcceptance_SweepDropsFirstSeen(t *testing.T) {
	srv := newATServer(t, atAxiosModel(t))
	manifest := writeManifest(t, map[string]string{"axios": "1.14.1", "left-pad": "1.3.0"})

	out, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(strings.ToLower(out), "first_seen") || strings.Contains(strings.ToLower(out), "first seen") {
		t.Errorf("table still has a first-seen column:\n%s", out)
	}

	rows, err := atSweepJSON(t, sweepDeps(t, srv.Server), manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(rows))
	}
	for _, r := range rows {
		if _, ok := r["first_seen"]; ok {
			t.Errorf("row %v has a first_seen key", r["package"])
		}
	}
}

// AT-12.11: a yarn.lock with no sibling package.json is an operational error
// (exit 1), not a usage error, and sends nothing.
func TestAcceptance_SweepYarnLockWithoutPackageJSON(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_not_found.json"))
	path := filepath.Join(t.TempDir(), "yarn.lock")
	lock := "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n" +
		"axios@^1.14.0:\n  version \"1.14.1\"\n  resolved \"https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz\"\n"
	if err := os.WriteFile(path, []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", path)
	if err == nil {
		t.Fatal("want an error for yarn.lock without package.json, got nil")
	}
	if code := exitcode.FromError(err); code != exitcode.Operational {
		t.Errorf("exit code = %d (err %T: %v), want %d", code, err, err, exitcode.Operational)
	}
	if n := len(srv.requests()); n != 0 {
		t.Errorf("want zero requests, got %d", n)
	}
}

// AT-12.13: an unrecognised manifest name is a usage error (exit 2) that lists
// every supported manifest, including pnpm-lock.yaml and yarn.lock.
func TestAcceptance_SweepUnknownManifestListsSupported(t *testing.T) {
	srv := newATServer(t, atAlways(t, "check_not_found.json"))
	path := filepath.Join(t.TempDir(), "Gemfile.lock")
	if err := os.WriteFile(path, []byte("GEM\n  specs:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runSweepCmd(t, sweepDeps(t, srv.Server), "-f", path)
	usage := atWantUsageNoRequests(t, srv, err)
	for _, name := range []string{"package.json", "package-lock.json", "requirements.txt", "poetry.lock", "pnpm-lock.yaml", "yarn.lock"} {
		if !strings.Contains(usage.Error(), name) {
			t.Errorf("usage message does not list %s: %s", name, usage.Error())
		}
	}
}
