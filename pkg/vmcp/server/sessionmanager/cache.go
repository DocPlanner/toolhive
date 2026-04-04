// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package sessionmanager

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// ErrExpired is returned by the check function passed to newRestorableCache to
// signal that a cached entry has definitively expired and should be evicted.
var ErrExpired = errors.New("cache entry expired")

// errSentinelFound is returned inside the singleflight load function when a
// non-V value (e.g. terminatedSentinel) is present in the map. Returning an
// error aborts the load and causes Get to return (zero, false), consistent
// with the behaviour of the initial-hit path that also returns (zero, false)
// for non-V values.
var errSentinelFound = errors.New("sentinel stored in cache")

// RestorableCache is a node-local write-through cache backed by a sync.Map,
// with singleflight-deduplicated restore on cache miss and lazy liveness
// validation on cache hit.
//
// Type parameter K is the key type (must be comparable).
// Type parameter V is the cached value type.
//
// Values are stored internally as any, which allows callers to place sentinel
// markers alongside V entries (e.g. a tombstone during teardown). Get performs
// a type assertion to V and treats non-V entries as "not found". Peek and
// Store expose raw any access for sentinel use.
type RestorableCache[K comparable, V any] struct {
	m      sync.Map
	touch  sync.Map
	flight singleflight.Group

	// load is called on a cache miss. Return (value, nil) on success.
	// A successful result is stored in the cache before being returned.
	load func(key K) (V, error)

	// check is called on every cache hit to confirm liveness. Returning nil
	// means the entry is alive. Returning ErrExpired means it has definitively
	// expired (the entry is evicted). Any other error is treated as a transient
	// failure and the cached value is returned unchanged.
	check func(key K) error

	// onEvict is called after a confirmed-expired entry has been removed. The
	// evicted value is passed to allow resource cleanup (e.g. closing
	// connections). May be nil.
	onEvict func(key K, v V)

	sweepStopCh   chan struct{}
	sweepStopOnce sync.Once
}

type cacheTouch struct {
	lastTouchNano atomic.Int64
}

func newCacheTouch(now time.Time) *cacheTouch {
	entry := &cacheTouch{}
	entry.lastTouchNano.Store(now.UnixNano())
	return entry
}

func (c *cacheTouch) touch(now time.Time) {
	c.lastTouchNano.Store(now.UnixNano())
}

func (c *cacheTouch) lastTouch() time.Time {
	return time.Unix(0, c.lastTouchNano.Load())
}

const minSweepInterval = time.Millisecond

func newRestorableCache[K comparable, V any](
	load func(K) (V, error),
	check func(K) error,
	onEvict func(K, V),
) *RestorableCache[K, V] {
	return &RestorableCache[K, V]{
		load:    load,
		check:   check,
		onEvict: onEvict,
	}
}

func (c *RestorableCache[K, V]) recordTouch(key K, now time.Time) {
	if existing, ok := c.touch.Load(key); ok {
		if tracked, ok := existing.(*cacheTouch); ok {
			tracked.touch(now)
			return
		}
	}
	c.touch.Store(key, newCacheTouch(now))
}

// Get returns the cached V value for key.
//
// On a cache hit, check is run first: ErrExpired evicts the entry and returns
// (zero, false); transient errors return the cached value unchanged. Non-V
// values stored via Store (e.g. sentinels) return (zero, false) without
// triggering a restore.
//
// On a cache miss, load is called under a singleflight group so at most one
// restore runs concurrently per key.
func (c *RestorableCache[K, V]) Get(key K) (V, bool) {
	if raw, ok := c.m.Load(key); ok {
		v, isV := raw.(V)
		if !isV {
			var zero V
			return zero, false
		}
		if err := c.check(key); err != nil {
			if errors.Is(err, ErrExpired) {
				c.m.Delete(key)
				c.touch.Delete(key)
				if c.onEvict != nil {
					c.onEvict(key, v)
				}
				var zero V
				return zero, false
			}
			// Transient error — keep the cached value.
		}
		c.recordTouch(key, time.Now())
		return v, true
	}

	// Cache miss: use singleflight to prevent concurrent restores for the same key.
	type result struct{ v V }
	raw, err, _ := c.flight.Do(fmt.Sprint(key), func() (any, error) {
		// Re-check the cache: a concurrent singleflight group may have stored
		// the value between our miss check above and acquiring this group.
		if stored, ok := c.m.Load(key); ok {
			if v, isV := stored.(V); isV {
				return result{v: v}, nil
			}
			// Non-V sentinel present (e.g. terminatedSentinel). Treat as a
			// hard stop: do not call load() and do not overwrite the sentinel.
			return nil, errSentinelFound
		}
		v, loadErr := c.load(key)
		if loadErr != nil {
			return nil, loadErr
		}
		// Guard against a sentinel being stored between load() completing and
		// this Store call (Terminate() running concurrently). LoadOrStore is
		// atomic: if a sentinel got in, we discard the freshly loaded value
		// via onEvict rather than silently overwriting the sentinel.
		if _, loaded := c.m.LoadOrStore(key, v); loaded {
			if c.onEvict != nil {
				c.onEvict(key, v)
			}
			return nil, errSentinelFound
		}
		c.recordTouch(key, time.Now())
		return result{v: v}, nil
	})
	if err != nil {
		var zero V
		return zero, false
	}
	r, ok := raw.(result)
	return r.v, ok
}

// Store sets key to value. value may be any type, including sentinel markers.
func (c *RestorableCache[K, V]) Store(key K, value any) {
	c.m.Store(key, value)
	if _, ok := value.(V); ok {
		c.recordTouch(key, time.Now())
		return
	}
	c.touch.Delete(key)
}

// Delete removes key from the cache.
func (c *RestorableCache[K, V]) Delete(key K) {
	c.m.Delete(key)
	c.touch.Delete(key)
}

// Peek returns the raw value stored under key without type assertion, liveness
// check, or restore. Used for sentinel inspection.
func (c *RestorableCache[K, V]) Peek(key K) (any, bool) {
	return c.m.Load(key)
}

// CompareAndSwap atomically replaces the value stored under key from old to
// new. Both old and new may be any type, including sentinels.
func (c *RestorableCache[K, V]) CompareAndSwap(key K, old, replacement any) bool {
	swapped := c.m.CompareAndSwap(key, old, replacement)
	if !swapped {
		return false
	}
	if _, ok := replacement.(V); ok {
		c.recordTouch(key, time.Now())
	} else {
		c.touch.Delete(key)
	}
	return true
}

// Touch refreshes the local idle deadline for a cached V entry.
// It returns false when the key is absent or currently stores a sentinel.
func (c *RestorableCache[K, V]) Touch(key K) bool {
	raw, ok := c.m.Load(key)
	if !ok {
		return false
	}
	if _, isV := raw.(V); !isV {
		return false
	}
	c.recordTouch(key, time.Now())
	return true
}

// StartSweep evicts idle cached V entries whose local touch timestamp has aged
// past maxAge. This bounds the lifetime of node-local runtime state without
// touching the shared storage backend, so Redis TTLs are not refreshed by the
// sweep itself.
func (c *RestorableCache[K, V]) StartSweep(maxAge, interval time.Duration) {
	if maxAge <= 0 || c.sweepStopCh != nil {
		return
	}
	if interval <= 0 {
		interval = maxAge / 2
	}
	if interval < minSweepInterval {
		interval = minSweepInterval
	}

	c.sweepStopCh = make(chan struct{})
	go c.sweepLoop(maxAge, interval)
}

// StopSweep stops the background idle-entry sweep when one is running.
func (c *RestorableCache[K, V]) StopSweep() {
	if c.sweepStopCh == nil {
		return
	}
	c.sweepStopOnce.Do(func() {
		close(c.sweepStopCh)
	})
}

func (c *RestorableCache[K, V]) sweepLoop(maxAge, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.evictIdle(maxAge)
		case <-c.sweepStopCh:
			return
		}
	}
}

func (c *RestorableCache[K, V]) evictIdle(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	type candidate struct {
		key   K
		raw   any
		value V
		touch *cacheTouch
	}

	var candidates []candidate
	c.touch.Range(func(rawKey, rawTouch any) bool {
		key, ok := rawKey.(K)
		if !ok {
			c.touch.Delete(rawKey)
			return true
		}
		touched, ok := rawTouch.(*cacheTouch)
		if !ok {
			c.touch.Delete(key)
			return true
		}
		if touched.lastTouch().After(cutoff) {
			return true
		}
		rawValue, ok := c.m.Load(key)
		if !ok {
			c.touch.Delete(key)
			return true
		}
		value, ok := rawValue.(V)
		if !ok {
			c.touch.Delete(key)
			return true
		}
		candidates = append(candidates, candidate{
			key:   key,
			raw:   rawValue,
			value: value,
			touch: touched,
		})
		return true
	})

	for _, item := range candidates {
		if item.touch.lastTouch().After(cutoff) {
			continue
		}
		if !c.m.CompareAndDelete(item.key, item.raw) {
			continue
		}
		c.touch.Delete(item.key)
		if c.onEvict != nil {
			c.onEvict(item.key, item.value)
		}
	}
}
