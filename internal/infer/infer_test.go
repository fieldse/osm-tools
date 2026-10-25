package infer

import "testing"

func TestType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.2.3.4", TypeIP},
		{"2001:db8::1", TypeIP},
		{"nginx:latest", TypeDocker},
		{"ghcr.io/owner/image", TypeDocker},
		{"docker.io/library/nginx", TypeDocker},
		{"models.litellm.cloud", TypeDomain},
		{"evil.com", TypeDomain},
		{"express", TypePackage},
		{"left-pad", TypePackage},
		{"https://github.com/owner/repo", TypeURL},
		{"HTTP://example.com/payload", TypeURL},
		{"0x1234567890abcdef1234567890abcdef12345678", TypeWallet},
		{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", TypeWallet},
		{"0x1234", TypePackage},
		{"aquasec/trivy:0.69.5", TypeDocker},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := Type(tt.input); got != tt.want {
				t.Errorf("Type(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsSupported(t *testing.T) {
	for _, ok := range []string{TypePackage, TypeDomain, TypeIP, TypeDocker} {
		if !IsSupported(ok) {
			t.Errorf("IsSupported(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "wallet", "repo", "Package"} {
		if IsSupported(bad) {
			t.Errorf("IsSupported(%q) = true, want false", bad)
		}
	}
}

func TestIsUnsupportedAsset(t *testing.T) {
	for _, bad := range []string{TypeRepository, TypeURL, TypeWallet} {
		if !IsUnsupportedAsset(bad) {
			t.Errorf("IsUnsupportedAsset(%q) = false, want true", bad)
		}
	}
	for _, ok := range []string{TypePackage, TypeDomain, TypeIP, TypeDocker, ""} {
		if IsUnsupportedAsset(ok) {
			t.Errorf("IsUnsupportedAsset(%q) = true, want false", ok)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := map[string]string{
		"Evil.COM":  "evil.com",
		"evil.com.": "evil.com",
		"evil.com":  "evil.com",
	}
	for in, want := range tests {
		if got := NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
