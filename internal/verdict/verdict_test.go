package verdict

import (
	"testing"

	"github.com/fieldse/osm-tools/internal/client"
)

func TestIsExactVersion(t *testing.T) {
	for _, v := range []string{"1.2.3", "v1.2.3", "1.2.3-beta.1", "1.0-SNAPSHOT", "1.0rc1", "2",
		"1.0.post1", "2.0.0.dev1", "5.3.2.RELEASE", "5.4.0.Final", "1.0.0.beta1", "1.0.0.pre", "1!2.0"} {
		if !IsExactVersion(v) {
			t.Errorf("IsExactVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "^1.2.3", "~1.2.3", ">=1.0.0", "1.x", "1.2.X", "*", "latest", "1.2.3 - 2.0.0", "^1 || ^2", "workspace:*",
		"1.x.3", "1.0.x", "1.*", "1.0.*", "!2.0", "1!", "v"} {
		if IsExactVersion(v) {
			t.Errorf("IsExactVersion(%q) = true, want false", v)
		}
	}
}

func TestOf(t *testing.T) {
	listed := client.CheckResult{Malicious: true, Details: client.Details{VersionInfo: "1.14.1, 0.30.4"}}
	all := client.CheckResult{Malicious: true, Details: client.Details{VersionInfo: "all"}}
	tests := []struct {
		name     string
		r        client.CheckResult
		sent     string
		fallback bool
		want     Status
	}{
		{"listed versions, none sent", listed, "", false, Review},
		{"listed versions, range sent", listed, "^1.14.0", false, Review},
		{"listed versions, exact sent", listed, "1.14.1", false, Malicious},
		{"listed versions, dotted qualifier sent", listed, "5.4.0.Final", false, Malicious},
		{"all versions", all, "", false, Malicious},
		{"blank version_info", client.CheckResult{Malicious: true}, "", false, Malicious},
		{"warning", client.CheckResult{Warning: "known malicious versions"}, "9.9.9", false, Review},
		{"known versions", client.CheckResult{KnownMaliciousVersions: []string{"3.0.0"}}, "9.9.9", false, Review},
		{"empty warning fields", client.CheckResult{KnownMaliciousVersions: []string{}}, "9.9.9", false, Clean},
		{"not found", client.CheckResult{}, "", false, Clean},
		{"fallback hit", all, "", true, Review},
		{"fallback miss", client.CheckResult{}, "", true, Clean},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Of(tt.r, tt.sent, tt.fallback); got != tt.want {
				t.Errorf("Of = %s, want %s", got, tt.want)
			}
		})
	}
}
