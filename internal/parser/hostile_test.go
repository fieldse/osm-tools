package parser

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// Lockfiles come from repositories a CI job may not trust. These tests pin the
// guardrails: a size cap, regular files only, and bounded YAML decoding.

const hostileTimeout = 2 * time.Second

// parseWithin runs Parse(path) and fails if it does not return in time.
func parseWithin(t *testing.T, path string) ([]Package, error) {
	t.Helper()
	type result struct {
		pkgs []Package
		err  error
	}
	done := make(chan result, 1)
	go func() {
		pkgs, err := Parse(path)
		done <- result{pkgs, err}
	}()
	select {
	case r := <-done:
		return r.pkgs, r.err
	case <-time.After(hostileTimeout):
		t.Fatalf("Parse(%q) did not return within %s", path, hostileTimeout)
		return nil, nil
	}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHostile_OversizedManifestRejected(t *testing.T) {
	for _, name := range []string{"pnpm-lock.yaml", "package.json", "requirements.txt"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, maxManifestBytes+1); err != nil {
				t.Fatal(err)
			}
			_, err := parseWithin(t, path)
			if err == nil || !strings.Contains(err.Error(), "MiB") {
				t.Fatalf("want a size-limit error, got %v", err)
			}
		})
	}
}

func TestHostile_BillionLaughsPnpm(t *testing.T) {
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\na0: &a0 [lol, lol, lol, lol, lol, lol, lol, lol, lol]\n")
	for i := 1; i <= 8; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [", i, i)
		for j := 0; j < 9; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "*a%d", i-1)
		}
		b.WriteString("]\n")
	}
	b.WriteString("importers: *a8\n")
	path := writeFile(t, t.TempDir(), "pnpm-lock.yaml", b.String())

	if _, err := parseWithin(t, path); err == nil {
		t.Fatal("want an error for an alias bomb, got nil")
	}
}

// TestHostile_QuadraticAliasPnpm: unique keys can still multiply work through
// two typed map levels (N importers each aliasing one N-entry deps map).
func TestHostile_QuadraticAliasPnpm(t *testing.T) {
	const n = 3000
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\nanchor:\n  dependencies: &deps\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "    d%d: {specifier: 1.0.0, version: 1.0.0}\n", i)
	}
	b.WriteString("importers:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  p%d: {dependencies: *deps}\n", i)
	}
	path := writeFile(t, t.TempDir(), "pnpm-lock.yaml", b.String())

	if _, err := parseWithin(t, path); err == nil {
		t.Fatal("want an excessive-aliasing error, got nil")
	}
}

func TestHostile_DeepNestingPnpm(t *testing.T) {
	body := "lockfileVersion: '9.0'\nimporters: " + strings.Repeat("[", 20000) + "\n"
	path := writeFile(t, t.TempDir(), "pnpm-lock.yaml", body)

	if _, err := parseWithin(t, path); err == nil {
		t.Fatal("want an error for deep nesting, got nil")
	}
}

func TestHostile_DecodeYAMLRecoversPanic(t *testing.T) {
	if err := decodeYAML([]byte("a: 1\n"), &panicker{}); err == nil {
		t.Fatal("want the decoder panic turned into an error")
	}
}

// panicker panics when the YAML decoder hands it a node.
type panicker struct{}

func (*panicker) UnmarshalYAML(func(any) error) error { panic("boom") }

func TestHostile_YarnSiblingPackageJSONSymlinkToDevice(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero on this platform")
	}
	dir := t.TempDir()
	lock := writeFile(t, dir, "yarn.lock", "# yarn lockfile v1\n\naxios@^1.14.0:\n  version \"1.14.1\"\n")
	if err := os.Symlink("/dev/zero", filepath.Join(dir, "package.json")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	_, err := parseWithin(t, lock)
	var usage *osmerr.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("want a not-a-regular-file UsageError, got %T: %v", err, err)
	}
}

func TestHostile_SymlinkedManifestRejected(t *testing.T) {
	for _, name := range []string{"yarn.lock", "package.json", "pnpm-lock.yaml"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := writeFile(t, dir, "secret.txt", "token=abc\n")
			writeFile(t, dir, "package.json", `{"dependencies":{"axios":"1.14.1"}}`)
			link := filepath.Join(t.TempDir(), name)
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}

			_, err := parseWithin(t, link)
			var usage *osmerr.UsageError
			if !errors.As(err, &usage) {
				t.Fatalf("want a not-a-regular-file UsageError, got %T: %v", err, err)
			}
		})
	}
}
