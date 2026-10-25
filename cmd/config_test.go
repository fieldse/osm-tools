package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/fieldse/osm-tools/internal/config"
	"github.com/fieldse/osm-tools/internal/osmerr"
)

const savedToken = "osm_saved0000000000wxyz"

// configRun executes runConfig with the given options and stdin, returning
// combined output and the error.
func configRun(t *testing.T, ctx context.Context, o configOptions, stdin io.Reader) (string, error) {
	t.Helper()
	cmd := newConfigCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(stdin)
	cmd.SetContext(ctx)
	err := runConfig(cmd, o)
	return out.String(), err
}

// storeWith returns a temp store, optionally pre-seeded with a token.
func storeWith(t *testing.T, token string) *config.Store {
	t.Helper()
	s := config.NewWithDir(t.TempDir())
	if token != "" {
		if err := s.Save(config.Config{Token: token}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func savedTokenIn(t *testing.T, s *config.Store) string {
	t.Helper()
	c, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c.Token
}

func tty() bool { return true }

func noEnv(string) string { return "" }

func secret(tok string) func(context.Context, io.Writer) (string, error) {
	return func(context.Context, io.Writer) (string, error) { return tok, nil }
}

func TestConfig_ShowMasksToken(t *testing.T) {
	s := storeWith(t, savedToken)
	var out bytes.Buffer
	cmd := newConfigCmd()
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	if err := runConfig(cmd, configOptions{show: true, store: s, getenv: noEnv}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, savedToken) {
		t.Fatalf("full token printed:\n%s", got)
	}
	for _, want := range []string{"Saved token: …wxyz", "OSM_API_KEY: not set"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestConfig_ShowReportsEnvOverrideAndNoToken(t *testing.T) {
	var out bytes.Buffer
	cmd := newConfigCmd()
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	env := func(k string) string {
		if k == "OSM_API_KEY" {
			return "osm_fromenv"
		}
		return ""
	}
	if err := runConfig(cmd, configOptions{show: true, store: storeWith(t, ""), getenv: env}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Saved token: none", "overrides the saved token"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

func TestConfig_ShowWorksWithoutTerminal(t *testing.T) {
	cmd := newConfigCmd()
	cmd.SetOut(io.Discard)
	cmd.SetContext(context.Background())
	notTTY := func() bool { return false }
	if err := runConfig(cmd, configOptions{show: true, store: storeWith(t, ""), getenv: noEnv, isTerminal: notTTY}); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestConfig_ExistingTokenDeclineKeepsIt(t *testing.T) {
	for _, answer := range []string{"\n", "n\n", "no\n", "whatever\n"} {
		s := storeWith(t, savedToken)
		called := false
		read := func(context.Context, io.Writer) (string, error) { called = true; return "osm_new", nil }
		out, err := configRun(t, context.Background(), configOptions{store: s, getenv: noEnv, isTerminal: tty, readSecret: read}, strings.NewReader(answer))
		if err != nil {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if called {
			t.Errorf("answer %q: token prompt shown after declining", answer)
		}
		if got := savedTokenIn(t, s); got != savedToken {
			t.Errorf("answer %q: token changed to %q", answer, got)
		}
		if !strings.Contains(out, "Kept the saved token.") {
			t.Errorf("answer %q: missing kept message:\n%s", answer, out)
		}
		if strings.Contains(out, savedToken) {
			t.Errorf("answer %q: full saved token printed at the confirm prompt:\n%s", answer, out)
		}
		if !strings.Contains(out, "…wxyz") {
			t.Errorf("answer %q: confirm prompt missing masked token:\n%s", answer, out)
		}
	}
}

func TestConfig_ExistingTokenAcceptReplacesIt(t *testing.T) {
	for _, answer := range []string{"y\n", "YES\n"} {
		s := storeWith(t, savedToken)
		_, err := configRun(t, context.Background(), configOptions{store: s, getenv: noEnv, isTerminal: tty, readSecret: secret("osm_replacement00000000")}, strings.NewReader(answer))
		if err != nil {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if got := savedTokenIn(t, s); got != "osm_replacement00000000" {
			t.Errorf("answer %q: token = %q", answer, got)
		}
	}
}

func TestConfig_NoTokenPromptsDirectly(t *testing.T) {
	s := storeWith(t, "")
	_, err := configRun(t, context.Background(), configOptions{store: s, getenv: noEnv, isTerminal: tty, readSecret: secret("osm_first0000000000000")}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if got := savedTokenIn(t, s); got != "osm_first0000000000000" {
		t.Errorf("token = %q", got)
	}
}

func TestConfig_CtrlCAtConfirmAbortsCleanly(t *testing.T) {
	s := storeWith(t, savedToken)
	pr, pw := io.Pipe() // never written: simulates a user who hasn't typed yet
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	done := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		cmd := newConfigCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetIn(pr)
		cmd.SetContext(ctx)
		done <- runConfig(cmd, configOptions{store: s, getenv: noEnv, isTerminal: tty, readSecret: secret("osm_never")})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("want nil (aborted), got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("config did not return after cancel")
	}
	if !strings.Contains(out.String(), "aborted") {
		t.Errorf("missing aborted message:\n%s", out.String())
	}
	if got := savedTokenIn(t, s); got != savedToken {
		t.Errorf("token changed to %q", got)
	}
}

func TestConfig_CtrlCAtTokenPromptAbortsCleanly(t *testing.T) {
	s := storeWith(t, "")
	read := func(ctx context.Context, _ io.Writer) (string, error) {
		<-ctx.Done()
		return "", errInterrupted
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	out, err := configRun(t, ctx, configOptions{store: s, getenv: noEnv, isTerminal: tty, readSecret: read}, strings.NewReader(""))
	if err != nil {
		t.Fatalf("want nil (aborted), got %v", err)
	}
	if !strings.Contains(out, "aborted") {
		t.Errorf("missing aborted message:\n%s", out)
	}
	if got := savedTokenIn(t, s); got != "" {
		t.Errorf("token saved after abort: %q", got)
	}
}

func TestConfig_CtrlDAtTokenPromptAbortsCleanly(t *testing.T) {
	s := storeWith(t, savedToken)
	read := func(context.Context, io.Writer) (string, error) {
		return "", fmt.Errorf("reading token: %w", io.EOF)
	}
	out, err := configRun(t, context.Background(), configOptions{store: s, getenv: noEnv, isTerminal: tty, readSecret: read}, strings.NewReader("y\n"))
	if err != nil {
		t.Fatalf("want nil (aborted), got %v", err)
	}
	if !strings.Contains(out, "aborted") {
		t.Errorf("missing aborted message:\n%s", out)
	}
	if got := savedTokenIn(t, s); got != savedToken {
		t.Errorf("token changed to %q", got)
	}
}

func TestConfig_NilContextFallsBackToBackground(t *testing.T) {
	s := storeWith(t, "")
	cmd := newConfigCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader(""))
	read := func(ctx context.Context, _ io.Writer) (string, error) {
		if ctx == nil {
			t.Fatal("readSecret got a nil context")
		}
		return "osm_first0000000000000", nil
	}
	if err := runConfig(cmd, configOptions{store: s, getenv: noEnv, isTerminal: tty, readSecret: read}); err != nil {
		t.Fatal(err)
	}
}

func TestConfig_NonTerminalIsUsageError(t *testing.T) {
	notTTY := func() bool { return false }
	_, err := configRun(t, context.Background(), configOptions{store: storeWith(t, ""), getenv: noEnv, isTerminal: notTTY}, strings.NewReader(""))
	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want UsageError, got %v", err)
	}
}

func TestReadLine_StopsAtNewline(t *testing.T) {
	r := strings.NewReader("y\nosm_rest")
	line, err := readLine(context.Background(), r)
	if err != nil || line != "y" {
		t.Fatalf("line=%q err=%v", line, err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "osm_rest" {
		t.Errorf("readLine consumed past the newline; rest=%q", rest)
	}
}

func TestReadRawLine(t *testing.T) {
	tests := []struct {
		name, in, want, rest string
		wantErr              error
	}{
		{"stops at newline", "osm_tok\nnext", "osm_tok", "next", nil},
		{"strips CRLF", "osm_tok\r\nnext", "osm_tok", "next", nil},
		{"partial line at EOF", "osm_tok", "osm_tok", "", nil},
		{"empty line", "\nnext", "", "next", nil},
		{"EOF before input", "", "", "", io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.in)
			line, err := readRawLine(context.Background(), r)
			if line != tt.want || !errors.Is(err, tt.wantErr) {
				t.Fatalf("line=%q err=%v, want line=%q err=%v", line, err, tt.want, tt.wantErr)
			}
			if rest, _ := io.ReadAll(r); string(rest) != tt.rest {
				t.Errorf("rest=%q, want %q", rest, tt.rest)
			}
		})
	}
}

func TestReadRawLine_ReadErrorPassesThrough(t *testing.T) {
	boom := errors.New("boom")
	_, err := readRawLine(context.Background(), io.MultiReader(strings.NewReader("osm_"), iotest.ErrReader(boom)))
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestReadRawLine_CancelInterrupts(t *testing.T) {
	pr, pw := io.Pipe() // never written: simulates a user who hasn't typed yet
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := readRawLine(ctx, pr); !errors.Is(err, errInterrupted) {
		t.Fatalf("want errInterrupted, got %v", err)
	}
}

func TestMaskToken(t *testing.T) {
	const short = "set (too short to preview)"
	tests := []struct {
		name, in, want string
	}{
		{"long", "osm_abcdefghijklmnop1234", "…1234"},
		{"short", "osm_q7z", short},
		{"19 chars", "osm_abcdefghijk1234", short},
		{"20 chars", "osm_abcdefghijkl1234", "…1234"},
		{"19 runes, more than 20 bytes", "osm_ééééééééééé1234", short},
		{"non-ASCII tail", "osm_abcdefghijklé日本ü", "…é日本ü"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskToken(tt.in); got != tt.want {
				t.Errorf("maskToken(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
