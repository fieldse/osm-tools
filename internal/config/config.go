// Package config persists CLI configuration to ~/.osm/config.json.
//
// This package is pure file I/O: it knows nothing about token-resolution
// precedence (see the auth resolver) or how the token is collected from the
// user (see the config command). The file holds a secret, so it is written
// 0600 inside a 0700 directory.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// dirName and fileName are the storage locations relative to the home dir.
const (
	dirName  = ".osm"
	fileName = "config.json"
)

// Config is the on-disk configuration.
type Config struct {
	Token string `json:"token,omitempty"`
}

// Store reads and writes the config file. The base directory is injectable so
// tests can point at t.TempDir() instead of the real home directory.
type Store struct {
	dir string
}

// New returns a Store rooted at the user's home directory (~/.osm).
func New() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locating home directory: %w", err)
	}
	return &Store{dir: filepath.Join(home, dirName)}, nil
}

// NewWithDir returns a Store rooted at an explicit directory. The config file
// lives at <dir>/config.json. Intended for tests.
func NewWithDir(dir string) *Store {
	return &Store{dir: dir}
}

// path is the full path to the config file.
func (s *Store) path() string {
	return filepath.Join(s.dir, fileName)
}

// Load reads the config file. A missing file is not an error: it returns a
// zero-value Config. A present-but-unparseable file is reported so the user
// can fix or remove it rather than silently losing settings.
func (s *Store) Load() (Config, error) {
	data, err := os.ReadFile(s.path())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("reading config %s: %w", s.path(), err)
	}

	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parsing config %s (remove it or fix the JSON): %w", s.path(), err)
	}
	return c, nil
}

// Save writes the config file, creating ~/.osm (0700) if needed and writing the
// file 0600 since it holds an API token.
func (s *Store) Save(c Config) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("creating config dir %s: %w", s.dir, err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}

	if err := os.WriteFile(s.path(), data, 0o600); err != nil {
		return fmt.Errorf("writing config %s: %w", s.path(), err)
	}
	return nil
}

// Path returns the config file path, for user-facing messages.
func (s *Store) Path() string {
	return s.path()
}
