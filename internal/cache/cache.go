// Package cache provides a 24h on-disk cache of check results, plus a decorator
// that wraps a lookup so cache hits are served before any API request is made.
//
// The cache sits outside the API client deliberately: a hit returns without
// issuing a request, so it never consumes a rate-limiter token. Only sweep uses
// it; check always queries fresh.
package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fieldse/osm-tools/internal/client"
)

// TTL is how long a cached entry is considered fresh.
const TTL = 24 * time.Hour

const (
	dirName  = ".osm"
	fileName = "cache.json"
)

// schemaVersion identifies the cache file layout and the CheckResult fields it
// holds. Bump it when the verdict starts reading a field that older entries
// lack, so those entries are discarded instead of read as CLEAN.
const schemaVersion = 2

// fileFormat is the on-disk shape. Files without the current schema are
// treated as empty; older binaries fail to decode this shape and start empty.
type fileFormat struct {
	Schema  int              `json:"schema"`
	Entries map[string]entry `json:"entries"`
}

// entry is a stored result with the time it was written.
type entry struct {
	Result   client.CheckResult `json:"result"`
	StoredAt time.Time          `json:"stored_at"`
}

// Cache is an in-memory map of results loaded from disk. It is safe for
// concurrent use. The file is read once on Load and written once on Flush to
// avoid per-write storms during a sweep.
type Cache struct {
	path string
	now  func() time.Time

	mu      sync.RWMutex
	entries map[string]entry
	dirty   bool
}

// New returns a Cache backed by ~/.osm/cache.json.
func New() (*Cache, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locating home directory: %w", err)
	}
	return NewWithPath(filepath.Join(home, dirName, fileName)), nil
}

// NewWithPath returns a Cache backed by an explicit file path. Intended for
// tests.
func NewWithPath(path string) *Cache {
	return &Cache{
		path:    path,
		now:     time.Now,
		entries: make(map[string]entry),
	}
}

// Load reads the cache file into memory. A missing file is not an error (the
// cache starts empty). A corrupt file, or one written with another schema
// version, is tolerated the same way so a bad cache can't break a sweep.
func (c *Cache) Load() error {
	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading cache %s: %w", c.path, err)
	}

	var stored fileFormat
	if err := json.Unmarshal(data, &stored); err != nil || stored.Schema != schemaVersion || stored.Entries == nil {
		return nil
	}

	c.mu.Lock()
	c.entries = stored.Entries
	c.mu.Unlock()
	return nil
}

// Get returns a cached result if present and still fresh.
func (c *Cache) Get(key string) (client.CheckResult, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return client.CheckResult{}, false
	}
	if c.now().Sub(e.StoredAt) > TTL {
		return client.CheckResult{}, false // stale: lazy expiry, leave on disk
	}
	return e.Result, true
}

// Set stores a result with the current timestamp.
func (c *Cache) Set(key string, result client.CheckResult) {
	c.mu.Lock()
	c.entries[key] = entry{Result: result, StoredAt: c.now()}
	c.dirty = true
	c.mu.Unlock()
}

// Flush writes the in-memory cache back to disk, creating ~/.osm (0700) if
// needed. It is a no-op if nothing changed. Call once at the end of a sweep
// (including on partial/cancelled runs to keep what was gathered).
func (c *Cache) Flush() error {
	c.mu.RLock()
	if !c.dirty {
		c.mu.RUnlock()
		return nil
	}
	data, err := json.MarshalIndent(fileFormat{Schema: schemaVersion, Entries: c.entries}, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("encoding cache: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}
	if err := os.WriteFile(c.path, data, 0o600); err != nil {
		return fmt.Errorf("writing cache %s: %w", c.path, err)
	}

	c.mu.Lock()
	c.dirty = false
	c.mu.Unlock()
	return nil
}
