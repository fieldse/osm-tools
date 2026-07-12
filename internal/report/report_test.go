package report

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// Tests for the pure report core. Case IDs map to docs/submit-report-spec.md
// "Testing". These are written against the frozen stub signatures; they are
// expected to fail (red) until Phase 2 implements the bodies.

// --- Type vocabulary (supports T2, T11, T13) ---

// TestIsValidType covers the 7 canonical report_type values plus the docker
// alias accepted, and rejects unknown/legacy values (e.g. "foo", "").
func TestIsValidType(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{TypePackage, true},
		{TypeContainer, true},
		{TypeRepository, true},
		{TypeURL, true},
		{TypeDomain, true},
		{TypeIP, true},
		{TypeWallet, true},
		{TypeDocker, true}, // CLI alias
		{"package", true},
		{"container", true},
		{"repository", true},
		{"url", true},
		{"domain", true},
		{"ip", true},
		{"wallet", true},
		{"docker", true},
		{"", false},
		{"foo", false},
		{"Package", false}, // case-sensitive
		{"CONTAINER", false},
		{"pkg", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := IsValidType(tt.in); got != tt.want {
				t.Errorf("IsValidType(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// --- Template parse/round-trip (T6) ---

// fullTemplate is a completely filled-in template used to assert every field is
// mapped by ParseTemplate.
const fullTemplate = `# Malicious postinstall in evil-pkg

- Type: package
- Resource: evil-pkg
- Package name: evil-pkg-core
- Registry: npm
- Publisher: badactor
- Contact: reporter@example.com
- Affected versions: 1.0.0, 1.0.1
- Severity: critical
- First seen: 2026-01-02T15:04:05Z
- Last seen: 2026-02-03T15:04:05Z
- OSV: https://osv.dev/GHSA-xxxx
- Tags: infostealer, npm

## Description
Steals env vars and posts them to a remote host.

## Payload / IOCs
Exfil to http://evil.com/collect from 10.0.0.1

## Evidence
- https://github.com/evil/repo
- https://npmjs.com/package/evil-pkg
`

// TestParseTemplate_FullReport parses a filled-in template into a Report with
// every field mapped, and confirms Registry (not ecosystem) and the evidence
// list are captured.
func TestParseTemplate_FullReport(t *testing.T) {
	got, err := ParseTemplate([]byte(fullTemplate))
	if err != nil {
		t.Fatalf("ParseTemplate returned error: %v", err)
	}

	want := Report{
		Type:               "package",
		ResourceID:         "evil-pkg",
		PackageName:        "evil-pkg-core",
		Registry:           "npm",
		Publisher:          "badactor",
		ContactEmail:       "reporter@example.com",
		VersionInfo:        "1.0.0, 1.0.1",
		SeverityLevel:      "critical",
		FirstSeen:          "2026-01-02T15:04:05Z",
		LastSeen:           "2026-02-03T15:04:05Z",
		OSVAdvisoryURL:     "https://osv.dev/GHSA-xxxx",
		Tags:               []string{"infostealer", "npm"},
		Description:        "Steals env vars and posts them to a remote host.",
		PayloadDescription: "Exfil to http://evil.com/collect from 10.0.0.1",
		EvidenceRefs:       []string{"https://github.com/evil/repo", "https://npmjs.com/package/evil-pkg"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseTemplate mismatch:\n got: %+v\nwant: %+v", got, want)
	}

	// Spot-check the fields the contract calls out explicitly.
	if got.Registry != "npm" {
		t.Errorf("Registry = %q, want npm (registry, not ecosystem)", got.Registry)
	}
	if len(got.EvidenceRefs) != 2 {
		t.Errorf("EvidenceRefs = %v, want 2 entries", got.EvidenceRefs)
	}
}

// TestTemplate_IsParseable asserts the blank Template() itself round-trips
// through ParseTemplate without error (the form documents its own shape), and
// that the placeholder angle-bracket hints parse as empty values.
func TestTemplate_IsParseable(t *testing.T) {
	tpl := Template()
	if strings.TrimSpace(tpl) == "" {
		t.Fatal("Template() returned empty string")
	}

	r, err := ParseTemplate([]byte(tpl))
	if err != nil {
		t.Fatalf("ParseTemplate(Template()) returned error: %v", err)
	}

	// The blank template's placeholder hints (<...>) must parse as empty, not
	// as literal "<...>" text.
	if strings.HasPrefix(r.Type, "<") || strings.HasPrefix(r.ResourceID, "<") ||
		strings.HasPrefix(r.Description, "<") {
		t.Errorf("placeholder hints leaked into fields: %+v", r)
	}
	for _, e := range r.EvidenceRefs {
		if strings.HasPrefix(e, "<") {
			t.Errorf("placeholder evidence entry leaked: %q", e)
		}
	}
}

// --- JSON parse (T6, T13) ---

// TestParseJSON_FullReport decodes an API-keyed JSON object into a Report,
// including evidence_references accepted as BOTH a JSON array and a
// pipe-delimited string.
func TestParseJSON_FullReport(t *testing.T) {
	want := Report{
		Type:               "package",
		ResourceID:         "evil-pkg",
		Description:        "Steals env vars.",
		PackageName:        "evil-pkg-core",
		Registry:           "npm",
		Publisher:          "badactor",
		ContactEmail:       "reporter@example.com",
		PayloadDescription: "Exfil to http://evil.com",
		SeverityLevel:      "critical",
		EvidenceRefs:       []string{"https://a.example/1", "https://b.example/2"},
		VersionInfo:        "1.0.0",
		FirstSeen:          "2026-01-02T15:04:05Z",
		LastSeen:           "2026-02-03T15:04:05Z",
		OSVAdvisoryURL:     "https://osv.dev/GHSA-xxxx",
		Tags:               []string{"infostealer", "npm"},
		Contributors:       []string{"alice", "bob"},
		DownloadCount:      42,
	}

	tests := []struct {
		name         string
		evidenceJSON string // the value used for the evidence_references key
	}{
		{"evidence as array", `["https://a.example/1", "https://b.example/2"]`},
		{"evidence as pipe string", `"https://a.example/1|https://b.example/2"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := `{
  "report_type": "package",
  "resource_identifier": "evil-pkg",
  "threat_description": "Steals env vars.",
  "package_name": "evil-pkg-core",
  "registry": "npm",
  "publisher": "badactor",
  "contact_email": "reporter@example.com",
  "payload_description": "Exfil to http://evil.com",
  "severity_level": "critical",
  "evidence_references": ` + tt.evidenceJSON + `,
  "version_info": "1.0.0",
  "first_seen": "2026-01-02T15:04:05Z",
  "last_seen": "2026-02-03T15:04:05Z",
  "osv_advisory_url": "https://osv.dev/GHSA-xxxx",
  "tags": ["infostealer", "npm"],
  "contributors": ["alice", "bob"],
  "download_count": 42
}`

			got, err := ParseJSON([]byte(src))
			if err != nil {
				t.Fatalf("ParseJSON returned error: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("ParseJSON mismatch:\n got: %+v\nwant: %+v", got, want)
			}
		})
	}
}

// TestParseJSON_UnknownKeyRejected asserts a misspelled key (e.g.
// "serverity_level") returns a *osmerr.UsageError instead of silently dropping.
func TestParseJSON_UnknownKeyRejected(t *testing.T) {
	src := `{
  "report_type": "package",
  "resource_identifier": "evil-pkg",
  "threat_description": "bad",
  "serverity_level": "critical"
}`

	_, err := ParseJSON([]byte(src))
	if err == nil {
		t.Fatal("ParseJSON accepted an unknown key, want error")
	}
	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want *osmerr.UsageError, got %T: %v", err, err)
	}
}

// --- Validation (T11, T12, T13) ---

// TestValidate_RequiredMissing covers absent Type / ResourceID / Description →
// *osmerr.UsageError, with empty warnings.
func TestValidate_RequiredMissing(t *testing.T) {
	tests := []struct {
		name string
		r    Report
	}{
		{
			name: "missing type",
			r:    Report{ResourceID: "evil-pkg", Description: "bad"},
		},
		{
			name: "missing resource_identifier",
			r:    Report{Type: "package", Description: "bad"},
		},
		{
			name: "missing description",
			r:    Report{Type: "package", ResourceID: "evil-pkg"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := Validate(tt.r)
			var usage *osmerr.UsageError
			if !errors.As(err, &usage) {
				t.Fatalf("want *osmerr.UsageError, got %T: %v", err, err)
			}
			if len(warnings) != 0 {
				t.Errorf("hard error should carry no warnings, got %v", warnings)
			}
		})
	}
}

// TestValidate_InvalidTypeIsError asserts an out-of-enum report_type is a
// UsageError (hard), while a minimal valid report passes.
func TestValidate_InvalidTypeIsError(t *testing.T) {
	t.Run("invalid type", func(t *testing.T) {
		_, err := Validate(Report{Type: "notatype", ResourceID: "x", Description: "y"})
		var usage *osmerr.UsageError
		if !errors.As(err, &usage) {
			t.Fatalf("want *osmerr.UsageError, got %T: %v", err, err)
		}
	})

	t.Run("valid passes", func(t *testing.T) {
		_, err := Validate(Report{Type: "package", ResourceID: "evil-pkg", Description: "steals creds"})
		if err != nil {
			t.Fatalf("valid report should not error, got %v", err)
		}
	})

	t.Run("docker alias passes", func(t *testing.T) {
		_, err := Validate(Report{Type: "docker", ResourceID: "nginx:latest", Description: "backdoored image"})
		if err != nil {
			t.Fatalf("docker alias should be valid, got %v", err)
		}
	})
}

// TestValidate_OptionalOnlyWarns asserts a report carrying a bad severity,
// non-ISO date, or unknown registry returns warnings with a nil error (never
// blocks).
func TestValidate_OptionalOnlyWarns(t *testing.T) {
	base := Report{Type: "package", ResourceID: "evil-pkg", Description: "steals creds"}

	tests := []struct {
		name   string
		mutate func(r Report) Report
	}{
		{
			name:   "unknown registry",
			mutate: func(r Report) Report { r.Registry = "cargo"; return r }, // not in ecosystem vocab
		},
		{
			name:   "bad severity",
			mutate: func(r Report) Report { r.SeverityLevel = "spicy"; return r },
		},
		{
			name:   "non-ISO first_seen",
			mutate: func(r Report) Report { r.FirstSeen = "yesterday"; return r },
		},
		{
			name:   "non-ISO last_seen",
			mutate: func(r Report) Report { r.LastSeen = "2026-01-02"; return r }, // date-only, not RFC3339
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := Validate(tt.mutate(base))
			if err != nil {
				t.Fatalf("soft problem should not error, got %v", err)
			}
			if len(warnings) == 0 {
				t.Errorf("expected at least one warning, got none")
			}
		})
	}
}
