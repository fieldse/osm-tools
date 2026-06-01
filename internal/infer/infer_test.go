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
