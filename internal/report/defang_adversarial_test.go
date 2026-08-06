package report

import "testing"

// Adversarial regression tests from the QA pass. Each encodes a confirmed
// defang leak or false-positive found after the initial green suite. Case
// labels reference the QA finding numbers (F2, F3, F4).

func TestDefang_URLWithAtSign_F2(t *testing.T) {
	// A credentialed URL (classic infostealer C2 form) must still be defanged;
	// the '@' must not cause the whole token to be skipped as if it were an email.
	tests := []struct {
		in       string
		wantGone string // substring that must NOT survive live
		wantHave string // substring that must be present after defang
	}{
		{"http://admin:admin@10.0.0.1/x", "http://admin:admin@10.0.0.1", "hxxp://"},
		{"http://user:pass@evil.com/", "://user:pass@evil.com", "evil[.]com"},
		{"http://evil.com/?redirect=a@b", "http://evil.com", "hxxp://evil[.]com"},
	}
	for _, tt := range tests {
		got := Defang(tt.in)
		if got == tt.in {
			t.Errorf("Defang(%q) left the token untouched (live IOC leak)", tt.in)
		}
		if !contains(got, tt.wantHave) {
			t.Errorf("Defang(%q) = %q; want it to contain %q", tt.in, got, tt.wantHave)
		}
	}
}

func TestDefang_PunctuationAdjacent_F3(t *testing.T) {
	// IOCs adjacent to prose punctuation are the common case in payload
	// descriptions; they must be neutralized, and the surrounding punctuation
	// preserved.
	tests := []struct {
		in   string
		want string
	}{
		{"connect to evil.com.", "connect to evil[.]com."},
		{"beacon 10.0.0.1, then", "beacon 10[.]0[.]0[.]1, then"},
		{"see (http://evil.com)", "see (hxxp://evil[.]com)"},
		{"(evil.com)", "(evil[.]com)"},
		{"host: evil.com; note", "host: evil[.]com; note"},
	}
	for _, tt := range tests {
		if got := Defang(tt.in); got != tt.want {
			t.Errorf("Defang(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	// Email adjacent to punctuation must STILL be skipped.
	if got := Defang("mail abuse@evil.com."); got != "mail abuse@evil.com." {
		t.Errorf("email should be left verbatim, got %q", got)
	}
}

func TestDefang_ClockTimeNotMangled_F4(t *testing.T) {
	// A time-of-day is a safe string, not an IPv6 IOC; incident write-ups are
	// full of them ("first beacon at 12:34:56").
	for _, in := range []string{"at 12:34:56 UTC", "deadline 08:00:00", "window 9:30 to 10:45"} {
		if got := Defang(in); got != in {
			t.Errorf("Defang(%q) = %q, want unchanged (clock time is not an IOC)", in, got)
		}
	}
	// A real IPv6 IOC must still be neutralized.
	if got := Defang("c2 at 2001:db8::1 now"); got == "c2 at 2001:db8::1 now" {
		t.Error("real IPv6 IOC was left verbatim")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
