// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package cache provides a generic, capacity-bounded cache with singleflight
// deduplication and per-hit liveness validation.
package cache

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sync/singleflight"
)

// ErrExpired is returned by the check function passed to New to signal that a
// cached entry has definitively expired and should be evicted.
var ErrExpired = errors.New("cache entry expired")

// ValidatingCache is a node-local write-through cache backed by a
// capacity-bounded LRU map, with singleflight-deduplicated Get operations and
// lazy liveness validation on cache hit.
//
// Type parameter K is the key type (must be comparable).
// Type parameter V is the cached value type.
//
// The entire Get operation — cache hit validation and miss load — runs under a
// singleflight group so at most one operation executes concurrently per key.
// Concurrent callers for the same key share the result, coalescing both
// liveness checks and storage round-trips into a single operation per key.
type ValidatingCache[K comparable, V any] struct {
	lruCache *lru.Cache[K, V]
	flight   singleflight.Group
	load     func(ctx context.Context, key K) (V, error)
	check    func(ctx context.Context, key K, val V) error
	onEvict  func(K, V)
	// mu serializes Set against the conditional eviction in getHit and in
	// EvictIdle. check() runs outside the lock to avoid holding it during I/O;
	// the lock is only held for the short Peek+Remove sequence.
	mu sync.Mutex
	// lastUsed records when each entry was last read or written (K -> time.Time).
	// EvictIdle reads it; the LRU eviction callback removes an entry's record.
	lastUsed sync.Map
	// detachMu guards detached.
	detachMu sync.Mutex
	// detached holds the entries that Remove and EvictIdle take out of the LRU
	// while holding mu. The LRU eviction callback skips onEvict for them; the
	// caller calls onEvict after releasing mu, so a slow onEvict (a session Close
	// doing backend I/O) never blocks Set or a concurrent eviction.
	detached map[K]V
}

// New creates a ValidatingCache with the given capacity and callbacks.
//
// capacity is the maximum number of entries; it must be >= 1. When the cache
// is full and a new entry must be stored, the least-recently-used entry is
// evicted first. Values less than 1 panic.
//
// load is called on a cache miss to restore the value; it must not be nil.
// check is called on every cache hit to confirm liveness. It receives both the
// key and the cached value so callers can inspect the value without a separate
// read. Returning ErrExpired evicts the entry; any other error is transient
// (cached value returned unchanged). It must not be nil.
// onEvict is called after any eviction (LRU or expiry); it may be nil.
func New[K comparable, V any](
	capacity int,
	load func(context.Context, K) (V, error),
	check func(context.Context, K, V) error,
	onEvict func(K, V),
) *ValidatingCache[K, V] {
	if capacity < 1 {
		panic(fmt.Sprintf("cache.New: capacity must be >= 1, got %d", capacity))
	}
	if load == nil {
		panic("cache.New: load must not be nil")
	}
	if check == nil {
		panic("cache.New: check must not be nil")
	}

	vc := &ValidatingCache[K, V]{
		load:     load,
		check:    check,
		onEvict:  onEvict,
		detached: make(map[K]V),
	}
	c, err := lru.NewWithEvict(capacity, func(key K, val V) {
		vc.lastUsed.Delete(key)
		if onEvict != nil && !vc.takeDetached(key, val) {
			onEvict(key, val)
		}
	})
	if err != nil {
		// Only possible if size < 0, which we have already ruled out above.
		panic(fmt.Sprintf("cache.New: lru.NewWithEvict: %v", err))
	}
	vc.lruCache = c
	return vc
}

// getHit validates a known-present cache entry and returns its value.
// If the entry has definitively expired it is evicted and (zero, false) is
// returned. Transient check errors leave the entry in place and return the
// cached value.
func (c *ValidatingCache[K, V]) getHit(ctx context.Context, key K, val V) (V, bool) {
	if err := c.check(ctx, key, val); err != nil {
		if errors.Is(err, ErrExpired) {
			// check() ran outside the lock to avoid holding it during I/O.
			// Re-verify under the lock that the entry hasn't been replaced by a
			// concurrent Set before removing it; otherwise we would evict a
			// freshly-written value that the caller intended to keep.
			c.mu.Lock()
			if current, ok := c.lruCache.Peek(key); ok && sameEntry(current, val) {
				// Remove fires the eviction callback automatically.
				c.lruCache.Remove(key)
			}
			c.mu.Unlock()
			var zero V
			return zero, false
		}
	}
	return val, true
}

// Get returns the value for key, loading it on a cache miss. The entire
// operation — cache hit validation and miss load — runs under a singleflight
// group so at most one operation executes concurrently per key. Concurrent
// callers for the same key share the result.
//
// ctx is forwarded to the load and check callbacks. When concurrent calls for
// the same key are coalesced by singleflight, only the first caller's context
// is forwarded; later callers' contexts are not used.
//
// On a cache hit the entry's liveness is validated via the check function
// provided to New: ErrExpired evicts the entry and falls through to load;
// transient errors return the cached value unchanged. On a cache miss, load
// is called to restore the value.
//
// The returned bool is false whenever the value is unavailable — either
// because load returned an error or because the key does not exist in the
// backing store. Callers cannot distinguish these two cases.
func (c *ValidatingCache[K, V]) Get(ctx context.Context, key K) (V, bool) {
	type result struct{ v V }
	// fmt.Sprint(key) is the singleflight key. For string keys this is
	// exact. For other types, distinct values with identical string
	// representations would be incorrectly coalesced — avoid non-string K
	// types unless their fmt.Sprint output is guaranteed unique.
	raw, err, _ := c.flight.Do(fmt.Sprint(key), func() (any, error) {
		// Cache hit path: validate liveness.
		if val, ok := c.lruCache.Get(key); ok {
			v, alive := c.getHit(ctx, key, val)
			if alive {
				c.lastUsed.Store(key, time.Now())
				return result{v: v}, nil
			}
			// Entry expired and evicted; fall through to load.
		}

		// Cache miss (or expired): load the value and store it.
		v, loadErr := c.load(ctx, key)
		if loadErr != nil {
			return nil, loadErr
		}

		// Guard against a concurrent Set that occurred while load() was running.
		// ContainsOrAdd stores only if absent; if a concurrent Set got in first,
		// their value wins and we return it instead.
		if alreadySet, _ := c.lruCache.ContainsOrAdd(key, v); alreadySet {
			if winner, ok := c.lruCache.Get(key); ok {
				// Winner confirmed: v is definitively discarded — release its resources.
				if c.onEvict != nil {
					c.onEvict(key, v)
				}
				c.lastUsed.Store(key, time.Now())
				return result{v: winner}, nil
			}
			// The concurrent winner was itself evicted by LRU pressure between
			// ContainsOrAdd and Get. Fall back to storing v — do NOT call onEvict
			// since v has not been released and is still valid.
			c.lruCache.Add(key, v)
		}
		c.lastUsed.Store(key, time.Now())
		return result{v: v}, nil
	})
	if err != nil {
		var zero V
		return zero, false
	}
	r, ok := raw.(result)
	return r.v, ok
}

// Set stores value under key, moving the entry to the MRU position. If the
// cache is at capacity, the least-recently-used entry is evicted first and
// onEvict is called for it.
func (c *ValidatingCache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lruCache.Add(key, value)
	c.lastUsed.Store(key, time.Now())
}

// Remove evicts key, calling onEvict for its value after the cache lock is
// released. It is a no-op when key is not cached.
func (c *ValidatingCache[K, V]) Remove(key K) {
	c.mu.Lock()
	val, removed := c.removeDetached(key)
	c.mu.Unlock()
	if removed && c.onEvict != nil {
		c.onEvict(key, val)
	}
}

// EvictIdle evicts every entry that no Get or Set has used for longer than
// maxAge, calling onEvict for each after the cache lock is released. It calls
// neither check nor load, so it never touches the backing store (for example, it
// does not refresh a Redis TTL).
//
// An entry that a concurrent Get returns just before EvictIdle removes it is
// still handed to that caller after onEvict has run.
func (c *ValidatingCache[K, V]) EvictIdle(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	c.lastUsed.Range(func(rawKey, rawUsed any) bool {
		key, okKey := rawKey.(K)
		used, okUsed := rawUsed.(time.Time)
		if !okKey || !okUsed || used.After(cutoff) {
			return true
		}
		c.mu.Lock()
		// CompareAndDelete skips an entry that a Get or Set touched after Range
		// read it; Set holds mu, so it cannot re-add the key in between.
		var (
			val     V
			removed bool
		)
		if c.lastUsed.CompareAndDelete(rawKey, rawUsed) {
			val, removed = c.removeDetached(key)
		}
		c.mu.Unlock()
		if removed && c.onEvict != nil {
			c.onEvict(key, val)
		}
		return true
	})
}

// Len returns the number of entries currently in the cache.
func (c *ValidatingCache[K, V]) Len() int {
	return c.lruCache.Len()
}

// removeDetached removes key from the LRU without running onEvict, and returns
// the removed value for the caller to release after it unlocks mu. The caller
// must hold mu. The LRU capacity eviction in Get does not hold mu, so it can
// evict the same entry concurrently; exactly one of the two calls onEvict for
// it. Peek and the detach mark happen under detachMu, which the eviction
// callback also takes: an eviction whose callback runs after the mark skips
// onEvict, and one that removed the entry before Peek leaves nothing to detach.
func (c *ValidatingCache[K, V]) removeDetached(key K) (V, bool) {
	c.detachMu.Lock()
	val, ok := c.lruCache.Peek(key)
	if ok {
		c.detached[key] = val
	}
	c.detachMu.Unlock()
	if !ok {
		var zero V
		return zero, false
	}
	c.lruCache.Remove(key)
	// Drop the mark if no callback took it: a concurrent eviction removed val
	// and a newer value for key took its place before Remove.
	c.takeDetached(key, val)
	return val, true
}

// takeDetached reports whether (key, val) is marked as detached, and clears the mark.
func (c *ValidatingCache[K, V]) takeDetached(key K, val V) bool {
	c.detachMu.Lock()
	defer c.detachMu.Unlock()
	marked, ok := c.detached[key]
	if !ok || !sameEntry(marked, val) {
		return false
	}
	delete(c.detached, key)
	return true
}

// sameEntry reports whether a and b are the same cache entry.
// For pointer types it compares addresses (identity), so a concurrent Set that
// stores a distinct new value is never mistaken for the stale entry. For
// non-pointer types it falls back to reflect.DeepEqual, which is safe for all
// comparable and non-comparable types.
func sameEntry[V any](a, b V) bool {
	ra := reflect.ValueOf(any(a))
	if ra.IsValid() {
		switch ra.Kind() { //nolint:exhaustive
		case reflect.Pointer, reflect.UnsafePointer:
			rb := reflect.ValueOf(any(b))
			return rb.IsValid() && ra.Pointer() == rb.Pointer()
		}
	}
	return reflect.DeepEqual(a, b)
}
