// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// DocPlanner fork: the auth server runs on Dragonfly, which by default rejects a
// Lua script that touches keys it did not declare in KEYS. Upstream's
// storeUpstreamTokensScript and casUpstreamTokensScript build the user-set keys
// at run time (ARGV[4]..userID), so the fork writes upstream tokens with
// WATCH/MULTI instead. These tests run the real code against a Dragonfly container.

const testDragonflyImage = "ghcr.io/dragonflydb/dragonfly:v1.38.1"

func startDragonfly(t *testing.T) *redis.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        testDragonflyImage,
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)

	client := redis.NewClient(&redis.Options{Addr: host + ":" + port.Port()})
	require.NoError(t, client.Ping(ctx).Err())
	return client
}

func TestIntegration_DragonflyUpstreamTokens(t *testing.T) {
	t.Parallel()

	client := startDragonfly(t)
	newStorage := func(t *testing.T) *RedisStorage {
		t.Helper()
		return NewRedisStorageWithClient(client, DeriveKeyPrefix("dragonfly", sanitizeTestName(t.Name())))
	}
	userSetHas := func(ctx context.Context, t *testing.T, s *RedisStorage, userID, sessionID string) bool {
		t.Helper()
		member := redisUpstreamKey(s.keyPrefix, sessionID, "provider-a")
		ok, err := client.SIsMember(ctx, s.keyPrefix+KeyTypeUserUpstream+":"+userID, member).Result()
		require.NoError(t, err)
		return ok
	}
	tokens := func(refresh, userID string) *UpstreamTokens {
		return &UpstreamTokens{
			AccessToken:  "access-" + refresh,
			RefreshToken: refresh,
			UserID:       userID,
			ExpiresAt:    time.Now().Add(time.Hour),
		}
	}

	t.Run("Lua with undeclared keys is rejected", func(t *testing.T) {
		ctx := t.Context()
		// The same pattern as upstream's scripts: a key built from ARGV.
		script := redis.NewScript(`return redis.call('SADD', ARGV[1] .. 'user', KEYS[1])`)
		err := script.Run(ctx, client, []string{"declared"}, "undeclared:").Err()
		require.Error(t, err, "Dragonfly must reject undeclared keys, else the fork's no-Lua patch can go")
	})

	t.Run("store keeps the user reverse index", func(t *testing.T) {
		ctx := t.Context()
		s := newStorage(t)
		require.NoError(t, s.StoreUpstreamTokens(ctx, "sess", "provider-a", tokens("r1", "user-1")))
		require.NoError(t, s.StoreUpstreamTokens(ctx, "sess", "provider-a", tokens("r2", "user-2")))

		got, err := s.GetUpstreamTokens(ctx, "sess", "provider-a")
		require.NoError(t, err)
		assert.Equal(t, "r2", got.RefreshToken)
		assert.False(t, userSetHas(ctx, t, s, "user-1", "sess"))
		assert.True(t, userSetHas(ctx, t, s, "user-2", "sess"))
	})

	t.Run("compare-and-swap", func(t *testing.T) {
		ctx := t.Context()
		s := newStorage(t)

		// "" matches a row that does not exist yet.
		require.NoError(t, s.CompareAndSwapUpstreamTokens(ctx, "sess", "provider-a", "", tokens("r1", "user-1")))

		// A stale expected value loses and leaves the row untouched.
		err := s.CompareAndSwapUpstreamTokens(ctx, "sess", "provider-a", "stale", tokens("r9", "user-9"))
		require.ErrorIs(t, err, ErrConcurrentRefresh)
		got, err := s.GetUpstreamTokens(ctx, "sess", "provider-a")
		require.NoError(t, err)
		assert.Equal(t, "r1", got.RefreshToken)
		assert.False(t, userSetHas(ctx, t, s, "user-9", "sess"))

		// The current value wins, and the reverse index follows the new user.
		require.NoError(t, s.CompareAndSwapUpstreamTokens(ctx, "sess", "provider-a", "r1", tokens("r2", "user-2")))
		got, err = s.GetUpstreamTokens(ctx, "sess", "provider-a")
		require.NoError(t, err)
		assert.Equal(t, "r2", got.RefreshToken)
		assert.False(t, userSetHas(ctx, t, s, "user-1", "sess"))
		assert.True(t, userSetHas(ctx, t, s, "user-2", "sess"))

		// A row that is gone does not match a non-empty expected value.
		require.NoError(t, s.DeleteUpstreamTokens(ctx, "sess"))
		err = s.CompareAndSwapUpstreamTokens(ctx, "sess", "provider-a", "r2", tokens("r3", "user-2"))
		require.ErrorIs(t, err, ErrConcurrentRefresh)
	})

	t.Run("concurrent compare-and-swap has one winner", func(t *testing.T) {
		ctx := t.Context()
		s := newStorage(t)
		require.NoError(t, s.StoreUpstreamTokens(ctx, "sess", "provider-a", tokens("r0", "user-1")))

		const writers = 8
		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			wins int
		)
		for i := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := s.CompareAndSwapUpstreamTokens(ctx, "sess", "provider-a", "r0",
					tokens("r1-"+string(rune('a'+i)), "user-1"))
				if err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
					return
				}
				assert.ErrorIs(t, err, ErrConcurrentRefresh)
			}()
		}
		wg.Wait()
		assert.Equal(t, 1, wins)
	})
}
