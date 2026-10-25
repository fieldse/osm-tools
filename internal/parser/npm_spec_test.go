package parser

import "testing"

func TestNpmSpec(t *testing.T) {
	tests := []struct {
		key, spec       string
		wantName, wantV string
		wantOK          bool
	}{
		{"a", "1.2.3", "a", "1.2.3", true},
		{"a", "v1.2.3", "a", "1.2.3", true},
		{"a", "= 1.2.3", "a", "1.2.3", true},
		{"a", "1.2.3+build.5", "a", "1.2.3+build.5", true},
		{"a", "1.2", "a", "", true},
		{"a", "1", "a", "", true},
		{"a", "next", "a", "", true},
		{"a", "", "a", "", true},
		{"alias", "npm:@scope/real", "@scope/real", "", true},
		{"alias", "npm:real@2.0.0", "real", "2.0.0", true},
		{"a", "owner/repo#v1.2.3", "", "", false},
		{"a", "github:owner/repo", "", "", false},
		{"a", "../local", "", "", false},
		{"a", "link:../x", "", "", false},
		{"alias", "npm:", "", "", false},
	}
	for _, tt := range tests {
		name, v, ok := npmSpec(tt.key, tt.spec)
		if name != tt.wantName || v != tt.wantV || ok != tt.wantOK {
			t.Errorf("npmSpec(%q, %q) = %q, %q, %v; want %q, %q, %v", tt.key, tt.spec, name, v, ok, tt.wantName, tt.wantV, tt.wantOK)
		}
	}
}

func TestPnpmVersion(t *testing.T) {
	tests := []struct {
		key, ref        string
		wantName, wantV string
		wantOK          bool
	}{
		{"vitest", "3.2.7(@types/node@22.20.0)(jsdom@25.0.1)", "vitest", "3.2.7", true},
		{"sw", "string-width@4.2.3", "string-width", "4.2.3", true},
		{"sw", "/string-width@4.2.3", "string-width", "4.2.3", true},
		{"s", "@scope/real@1.0.0", "@scope/real", "1.0.0", true},
		{"vitest", "3.2.7_@types+node@22.20.0", "vitest", "3.2.7", true},
		{"fork", "lodash_fork@1.0.0", "lodash_fork", "1.0.0", true},
		{"l", "link:../l", "", "", false},
		{"f", "file:vendor/f.tgz", "", "", false},
		{"w", "workspace:*", "", "", false},
		{"g", "github.com/owner/repo/abc123", "", "", false},
		{"t", "https://example.com/t.tgz", "", "", false},
	}
	for _, tt := range tests {
		name, v, ok := pnpmVersion(tt.key, tt.ref)
		if name != tt.wantName || v != tt.wantV || ok != tt.wantOK {
			t.Errorf("pnpmVersion(%q, %q) = %q, %q, %v; want %q, %q, %v", tt.key, tt.ref, name, v, ok, tt.wantName, tt.wantV, tt.wantOK)
		}
	}
}
