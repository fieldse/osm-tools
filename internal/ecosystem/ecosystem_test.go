package ecosystem

import "testing"

func TestAll(t *testing.T) {
	if len(All()) != 8 {
		t.Errorf("All() returned %d ecosystems, want 8", len(All()))
	}
	// Mutating the returned slice must not affect the canonical list.
	All()[0] = "mutated"
	if All()[0] != NPM {
		t.Error("All() returned a mutable view of the internal list")
	}
}

func TestIsValid(t *testing.T) {
	for _, ok := range All() {
		if !IsValid(ok) {
			t.Errorf("IsValid(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "cargo", "go-modules", "NPM"} {
		if IsValid(bad) {
			t.Errorf("IsValid(%q) = true, want false", bad)
		}
	}
}
