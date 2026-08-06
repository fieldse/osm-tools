package report

import (
	"strings"
	"testing"
)

// --- Defang (T14, T15, T16) ---

// TestDefang_NeutralizesIOCs covers URL, IPv4 (with CIDR/port), IPv6, and bare
// hostname rewrites to the platform convention.
func TestDefang_NeutralizesIOCs(t *testing.T) {
	// Exact-output cases where the contract pins the result.
	exact := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4 plain", "10.0.0.1", "10[.]0[.]0[.]1"},
		{"ipv4 with cidr", "10.0.0.0/8", "10[.]0[.]0[.]0/8"},
		{"ipv4 with port", "1.2.3.4:8080", "1[.]2[.]3[.]4:8080"},
		{"bare hostname", "evil.com", "evil[.]com"},
	}
	for _, tt := range exact {
		t.Run(tt.name, func(t *testing.T) {
			if got := Defang(tt.in); got != tt.want {
				t.Errorf("Defang(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	// Cases where we assert on structural properties rather than an exact
	// string (path/query handling is implementation-defined).
	t.Run("http url", func(t *testing.T) {
		got := Defang("http://evil.com/collect")
		if !strings.Contains(got, "hxxp://") {
			t.Errorf("Defang(%q) = %q, want scheme rewritten to hxxp://", "http://evil.com/collect", got)
		}
		if !strings.Contains(got, "evil[.]com") {
			t.Errorf("Defang(%q) = %q, want host dots defanged", "http://evil.com/collect", got)
		}
		if strings.Contains(got, "http://") {
			t.Errorf("Defang(%q) = %q, still contains live http:// scheme", "http://evil.com/collect", got)
		}
	})

	t.Run("https url", func(t *testing.T) {
		got := Defang("https://evil.com")
		if !strings.Contains(got, "hxxps://") {
			t.Errorf("Defang(%q) = %q, want scheme rewritten to hxxps://", "https://evil.com", got)
		}
		if !strings.Contains(got, "evil[.]com") {
			t.Errorf("Defang(%q) = %q, want host dots defanged", "https://evil.com", got)
		}
	})

	t.Run("ipv6 not verbatim", func(t *testing.T) {
		in := "2001:db8::1"
		got := Defang(in)
		if got == in {
			t.Errorf("Defang(%q) left IPv6 verbatim; want it neutralized", in)
		}
		if !strings.Contains(got, "[:]") {
			t.Errorf("Defang(%q) = %q, want colons defanged to [:]", in, got)
		}
	})
}

// TestDefang_LeavesSafeTextAlone covers prose, version strings (1.2.3), emails,
// and idempotency (re-defang is a no-op).
func TestDefang_LeavesSafeTextAlone(t *testing.T) {
	verbatim := []struct {
		name string
		in   string
	}{
		{"email", "abuse@evil.com"},
		{"version", "1.2.3"},
		{"v-version", "v1.2.3"},
		{"prose", "this is ordinary prose without any indicators"},
		{"three-octet not ip", "1.2.3"},
	}
	for _, tt := range verbatim {
		t.Run(tt.name, func(t *testing.T) {
			if got := Defang(tt.in); got != tt.in {
				t.Errorf("Defang(%q) = %q, want unchanged", tt.in, got)
			}
		})
	}

	// Idempotency: defanging already-defanged text is a no-op.
	idempotent := []string{
		"http://evil.com/collect",
		"https://evil.com",
		"10.0.0.1",
		"1.2.3.4:8080",
		"10.0.0.0/8",
		"evil.com",
		"2001:db8::1",
		"abuse@evil.com",
		"contact us at http://evil.com or 10.0.0.1",
	}
	for _, in := range idempotent {
		t.Run("idempotent/"+in, func(t *testing.T) {
			once := Defang(in)
			twice := Defang(once)
			if once != twice {
				t.Errorf("Defang not idempotent for %q: once=%q twice=%q", in, once, twice)
			}
		})
	}
}

// TestDefangPayload_OnlyTouchesPayload asserts DefangPayload rewrites
// PayloadDescription and leaves EvidenceRefs / OSVAdvisoryURL / Description
// untouched.
func TestDefangPayload_OnlyTouchesPayload(t *testing.T) {
	in := Report{
		Type:               "package",
		ResourceID:         "evil-pkg",
		Description:        "Contacts http://evil.com — this should NOT be defanged",
		PayloadDescription: "Exfil to http://evil.com from 10.0.0.1",
		EvidenceRefs:       []string{"http://evil.com/evidence"},
		OSVAdvisoryURL:     "https://osv.dev/GHSA-xxxx",
	}

	out := DefangPayload(in)

	// Payload must change (it contained live IOCs).
	if out.PayloadDescription == in.PayloadDescription {
		t.Errorf("PayloadDescription unchanged: %q", out.PayloadDescription)
	}
	if want := Defang(in.PayloadDescription); out.PayloadDescription != want {
		t.Errorf("PayloadDescription = %q, want %q", out.PayloadDescription, want)
	}

	// Every other field must be byte-identical to the input.
	if out.Description != in.Description {
		t.Errorf("Description changed: %q", out.Description)
	}
	if out.OSVAdvisoryURL != in.OSVAdvisoryURL {
		t.Errorf("OSVAdvisoryURL changed: %q", out.OSVAdvisoryURL)
	}
	if len(out.EvidenceRefs) != 1 || out.EvidenceRefs[0] != in.EvidenceRefs[0] {
		t.Errorf("EvidenceRefs changed: %v", out.EvidenceRefs)
	}
	if out.Type != in.Type || out.ResourceID != in.ResourceID {
		t.Errorf("identity fields changed: %+v", out)
	}
}
