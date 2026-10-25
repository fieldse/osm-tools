// Package termsafe makes untrusted text safe to print to a terminal.
package termsafe

import (
	"strings"
	"unicode"
)

// String replaces control characters and bidi overrides in s so that API or
// manifest text cannot move the cursor, rewrite lines, or reorder output.
// Tab, CR and LF become spaces; every other such rune becomes U+FFFD.
func String(s string) string {
	if !needsCleaning(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case unsafeRune(r):
			return unicode.ReplacementChar
		default:
			return r
		}
	}, s)
}

// Strings applies String to each element and returns a new slice.
func Strings(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = String(s)
	}
	return out
}

func needsCleaning(s string) bool {
	for _, r := range s {
		if unsafeRune(r) {
			return true
		}
	}
	return false
}

// unsafeRune covers C0, DEL and C1 controls plus the Unicode bidi controls.
func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)
}
