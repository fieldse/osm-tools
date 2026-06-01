package parser

import "testing"

func TestDedupe(t *testing.T) {
	in := []Package{
		{Name: "a", Version: "1", Ecosystem: "npm"},
		{Name: "a", Version: "1", Ecosystem: "npm"}, // dup
		{Name: "a", Version: "2", Ecosystem: "npm"}, // different version
		{Name: "b", Version: "1", Ecosystem: "npm"},
	}
	got := Dedupe(in)
	if len(got) != 3 {
		t.Fatalf("got %d packages, want 3: %+v", len(got), got)
	}
	// First-occurrence order preserved.
	if got[0].Name != "a" || got[0].Version != "1" {
		t.Errorf("order not preserved: %+v", got)
	}
}
