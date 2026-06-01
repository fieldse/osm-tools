package cache

import (
	"context"
	"strings"

	"github.com/fieldse/osm-tools/internal/client"
)

// Lookup is the check operation the cache decorates. *client.Client satisfies
// it directly. Defining it here (the consumer side) rather than in client keeps
// the interface where substitution actually happens.
type Lookup interface {
	Check(ctx context.Context, q client.Query) (client.CheckResult, error)
}

// Caching wraps a Lookup, serving fresh results from the cache and writing back
// on a miss. Because a hit returns before delegating, it never reaches the
// rate-limited transport.
type Caching struct {
	inner Lookup
	cache *Cache
}

// Wrap returns a caching decorator over inner.
func Wrap(inner Lookup, c *Cache) *Caching {
	return &Caching{inner: inner, cache: c}
}

// Check returns a fresh cached result if present, otherwise delegates to the
// inner lookup and stores the result.
func (d *Caching) Check(ctx context.Context, q client.Query) (client.CheckResult, error) {
	key := cacheKey(q)
	if r, ok := d.cache.Get(key); ok {
		return r, nil
	}

	r, err := d.inner.Check(ctx, q)
	if err != nil {
		return client.CheckResult{}, err
	}
	d.cache.Set(key, r)
	return r, nil
}

// cacheKey builds the entry key as type:ecosystem:name:version.
func cacheKey(q client.Query) string {
	return strings.Join([]string{q.Type, q.Ecosystem, q.Identifier, q.Version}, ":")
}
