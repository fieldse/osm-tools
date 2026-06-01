package cmd

import "testing"

func TestInferType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.2.3.4", typeIP},
		{"2001:db8::1", typeIP},
		{"nginx:latest", typeDocker},
		{"ghcr.io/owner/image", typeDocker},
		{"docker.io/library/nginx", typeDocker},
		{"models.litellm.cloud", typeDomain},
		{"evil.com", typeDomain},
		{"express", typePackage},
		{"left-pad", typePackage},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := inferType(tt.input); got != tt.want {
				t.Errorf("inferType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
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
		{"package with ecosystem", "express", "", "npm", typePackage, false},
		{"domain inferred, no ecosystem needed", "evil.com", "", "", typeDomain, false},
		{"ip inferred", "1.2.3.4", "", "", typeIP, false},
		{"explicit type override", "express", "domain", "", typeDomain, false},
		{"explicit package still needs ecosystem", "whatever", "package", "", "", true},
		{"unknown type flag", "x", "bogus", "", "", true},
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
