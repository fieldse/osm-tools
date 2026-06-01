package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	store := NewWithDir(t.TempDir())

	// Missing file loads as zero value, not an error.
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	if got.Token != "" {
		t.Errorf("missing file should be empty, got token %q", got.Token)
	}

	// Save then load returns the same token.
	if err := store.Save(Config{Token: "osm_abc123"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err = store.Load()
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if got.Token != "osm_abc123" {
		t.Errorf("round-trip token = %q, want osm_abc123", got.Token)
	}
}

func TestStoreCorruptFile(t *testing.T) {
	dir := t.TempDir()
	store := NewWithDir(dir)
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load(); err == nil {
		t.Fatal("expected error loading corrupt file, got nil")
	}
}

func TestStorePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission semantics")
	}
	dir := filepath.Join(t.TempDir(), "nested")
	store := NewWithDir(dir)

	if err := store.Save(Config{Token: "osm_secret"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %o, want 700", perm)
	}

	fileInfo, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("file perm = %o, want 600", perm)
	}
}
