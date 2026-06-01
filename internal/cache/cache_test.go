package cache

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fieldse/osm-tools/internal/client"
)

func tempCache(t *testing.T) *Cache {
	t.Helper()
	return NewWithPath(filepath.Join(t.TempDir(), "cache.json"))
}

func TestGetSetRoundTrip(t *testing.T) {
	c := tempCache(t)
	c.Set("k", client.CheckResult{Malicious: true})

	got, ok := c.Get("k")
	if !ok || !got.Malicious {
		t.Fatalf("expected fresh hit, got ok=%v result=%+v", ok, got)
	}
	if _, ok := c.Get("missing"); ok {
		t.Error("expected miss for unknown key")
	}
}

func TestTTLBoundary(t *testing.T) {
	c := tempCache(t)

	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	now := base
	c.now = func() time.Time { return now }

	c.Set("k", client.CheckResult{Malicious: true})

	// Just under TTL → hit.
	now = base.Add(TTL - time.Second)
	if _, ok := c.Get("k"); !ok {
		t.Error("entry just under TTL should be a hit")
	}

	// Just over TTL → miss.
	now = base.Add(TTL + time.Second)
	if _, ok := c.Get("k"); ok {
		t.Error("entry just over TTL should be a miss")
	}
}

func TestLoadMissingFile(t *testing.T) {
	c := tempCache(t)
	if err := c.Load(); err != nil {
		t.Fatalf("missing file should load cleanly, got %v", err)
	}
}

func TestLoadCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewWithPath(path)
	if err := c.Load(); err != nil {
		t.Fatalf("corrupt file should be tolerated, got %v", err)
	}
	if _, ok := c.Get("anything"); ok {
		t.Error("corrupt cache should behave as empty")
	}
}

func TestFlushAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")

	c1 := NewWithPath(path)
	c1.Set("k", client.CheckResult{SeverityLevel: "high"})
	if err := c1.Flush(); err != nil {
		t.Fatal(err)
	}

	c2 := NewWithPath(path)
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}
	got, ok := c2.Get("k")
	if !ok || got.SeverityLevel != "high" {
		t.Errorf("reloaded entry = %+v, ok=%v", got, ok)
	}
}

func TestFlushNoopWhenClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	c := NewWithPath(path)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("flush with no changes should not create a file")
	}
}

// stubLookup counts calls and returns a canned result.
type stubLookup struct {
	mu    sync.Mutex
	calls int
}

func (s *stubLookup) Check(_ context.Context, _ client.Query) (client.CheckResult, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return client.CheckResult{Malicious: true}, nil
}

func TestDecoratorHitMissWriteBack(t *testing.T) {
	stub := &stubLookup{}
	d := Wrap(stub, tempCache(t))
	q := client.Query{Type: "package", Ecosystem: "npm", Identifier: "evil", Version: "1.0.0"}

	// First call: miss → delegates.
	if _, err := d.Check(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	// Second call: hit → no delegation.
	if _, err := d.Check(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if stub.calls != 1 {
		t.Errorf("inner called %d times, want 1 (second should hit cache)", stub.calls)
	}
}

func TestDecoratorConcurrent(t *testing.T) {
	// Exercises the cache's locking under -race. The decorator does not
	// single-flight, so concurrent misses on the same key may both delegate;
	// we assert safety and correctness, not an exact call count.
	stub := &stubLookup{}
	c := tempCache(t)
	d := Wrap(stub, c)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			q := client.Query{Type: "package", Ecosystem: "npm", Identifier: "pkg", Version: string(rune('a' + n%5))}
			res, err := d.Check(context.Background(), q)
			if err != nil || !res.Malicious {
				t.Errorf("unexpected result: %+v err=%v", res, err)
			}
		}(i)
	}
	wg.Wait()

	// All 5 distinct keys should be cached after the run.
	for _, v := range []string{"a", "b", "c", "d", "e"} {
		if _, ok := c.Get("package:npm:pkg:" + v); !ok {
			t.Errorf("key for version %q not cached", v)
		}
	}
}
