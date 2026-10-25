package termsafe

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain text unchanged", "credential stealer", "credential stealer"},
		{"unicode text unchanged", "café ✓", "café ✓"},
		{"newline and CR become spaces", "a\r\nb\tc", "a  b c"},
		{"ESC replaced", "x\x1b[1Ay", "x�[1Ay"},
		{"DEL replaced", "a\x7fb", "a�b"},
		{"C1 CSI replaced", "a\u009bb", "a�b"},
		{"bidi override replaced", "a‮b", "a�b"},
		{"OSC 52 neutralised", "\x1b]52;c;ZXZpbA==\x07", "�]52;c;ZXZpbA==�"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := String(tt.in); got != tt.want {
				t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestStringsCopies(t *testing.T) {
	in := []string{"ok", "bad\x1b"}
	got := Strings(in)
	if in[1] != "bad\x1b" {
		t.Errorf("input slice was modified: %q", in)
	}
	if strings.ContainsRune(got[1], 0x1b) {
		t.Errorf("Strings left ESC in %q", got[1])
	}
}
