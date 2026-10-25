package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"testing"
)

// atLatestModel answers query-latest with an empty threat list echoing the
// requested ecosystem.
func atLatestModel() atResponder {
	return func(_ string, q url.Values) (int, []byte) {
		body, _ := json.Marshal(map[string]any{"ecosystem": q.Get("ecosystem"), "count": 0, "threats": []any{}})
		return http.StatusOK, body
	}
}

// runLatestAT executes the latest command against deps, capturing stdout.
func runLatestAT(t *testing.T, deps *appDeps, args ...string) (string, error) {
	t.Helper()
	cmd := newLatestCmd(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// atLatestEcosystems returns the ecosystem param of each recorded request,
// sorted, failing on any request that is not a single-ecosystem query-latest.
func atLatestEcosystems(t *testing.T, srv *atServer) []string {
	t.Helper()
	var ecos []string
	for _, r := range srv.requests() {
		if r.Path != "/query-latest" {
			t.Errorf("unexpected request path %q", r.Path)
		}
		ecos = append(ecos, atOne(t, r, "ecosystem"))
	}
	sort.Strings(ecos)
	return ecos
}

func atSorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func atEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// atGroupKeys decodes latest output and returns its ecosystem keys, sorted.
func atGroupKeys(t *testing.T, out string) []string {
	t.Helper()
	var grouped map[string]any
	if err := json.Unmarshal([]byte(out), &grouped); err != nil {
		t.Fatalf("latest output is not a JSON object: %v\n%s", err, out)
	}
	var keys []string
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// AT-5.1: latest -e vscode,openvsx,skills,brew is accepted and sends exactly
// one request per ecosystem.
func TestAcceptance_LatestAcceptsNewEcosystems(t *testing.T) {
	want := []string{"vscode", "openvsx", "skills", "brew"}
	srv := newATServer(t, atLatestModel())
	out, err := runLatestAT(t, testDeps(srv.Server), "-e", "vscode,openvsx,skills,brew")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := atLatestEcosystems(t, srv); !atEqual(got, atSorted(want)) {
		t.Errorf("requested ecosystems = %v, want one each of %v", got, atSorted(want))
	}
	if got := atGroupKeys(t, out); !atEqual(got, atSorted(want)) {
		t.Errorf("output groups = %v, want %v", got, atSorted(want))
	}
}

// AT-5.2: latest with no -e queries all 12 package ecosystems exactly once
// each.
func TestAcceptance_LatestDefaultsToAllTwelve(t *testing.T) {
	srv := newATServer(t, atLatestModel())
	out, err := runLatestAT(t, testDeps(srv.Server))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := atSorted(atPackageEcosystems)
	if got := atLatestEcosystems(t, srv); !atEqual(got, want) {
		t.Errorf("requested ecosystems = %v, want one each of %v", got, want)
	}
	if got := atGroupKeys(t, out); !atEqual(got, want) {
		t.Errorf("output groups = %v, want %v", got, want)
	}
}

// AT-5.3: regression guard. latest -e cargo is a usage error and sends
// nothing.
func TestAcceptance_LatestRejectsCargo(t *testing.T) {
	srv := newATServer(t, atLatestModel())
	_, err := runLatestAT(t, testDeps(srv.Server), "-e", "cargo")
	atWantUsageNoRequests(t, srv, err)
}

// AT-8.4: latest JSON keeps resource_identifier, status, osm_url and
// verified_at from the API response.
func TestAcceptance_LatestKeepsThreatFields(t *testing.T) {
	srv := newATServer(t, atAlways(t, "latest_npm.json"))
	out, err := runLatestAT(t, testDeps(srv.Server), "-e", "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var grouped map[string][]map[string]any
	if err := json.Unmarshal([]byte(out), &grouped); err != nil {
		t.Fatalf("latest output is not grouped JSON: %v\n%s", err, out)
	}
	threats := grouped["npm"]
	if len(threats) != 1 {
		t.Fatalf("want 1 npm threat, got %d: %v", len(threats), grouped)
	}
	want := map[string]string{
		"resource_identifier": "npm/evil-npm-pkg",
		"status":              "verified",
		"osm_url":             "https://opensourcemalware.com/npm/evil-npm-pkg",
		"verified_at":         "2026-10-24T18:22:05.704+00:00",
	}
	for k, v := range want {
		if got, ok := threats[0][k]; !ok || got != v {
			t.Errorf("%s = %v (present=%v), want %q", k, got, ok, v)
		}
	}
}
