package osmerr

import (
	"strings"
	"testing"
)

func TestAPIErrorBodyNeutralised(t *testing.T) {
	e := &APIError{StatusCode: 500, Body: "oops\x1b[2K\r\nosm: all clear", RetryAfter: "1\x1b"}
	if msg := e.Error(); strings.ContainsAny(msg, "\x1b\r\n") {
		t.Errorf("Error() kept control characters: %q", msg)
	}
}

func TestAPIErrorKeepsBodyText(t *testing.T) {
	e := &APIError{StatusCode: 429, Body: `{"error":"Daily quota exceeded"}`}
	if msg := e.Error(); !strings.Contains(msg, "Daily quota exceeded") || !strings.Contains(msg, "429") {
		t.Errorf("Error() = %q, want status and body text", msg)
	}
}
