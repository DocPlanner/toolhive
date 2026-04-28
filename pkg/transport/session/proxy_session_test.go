// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestResolveSessionTTLFromEnv(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		t.Setenv(ProxySessionTTLEnvVar, "")

		assert.Equal(t, DefaultSessionTTL, ResolveSessionTTLFromEnv())
	})

	t.Run("valid duration", func(t *testing.T) {
		t.Setenv(ProxySessionTTLEnvVar, "24h")

		assert.Equal(t, 24*time.Hour, ResolveSessionTTLFromEnv())
	})

	t.Run("invalid duration falls back", func(t *testing.T) {
		t.Setenv(ProxySessionTTLEnvVar, "not-a-duration")

		assert.Equal(t, DefaultSessionTTL, ResolveSessionTTLFromEnv())
	})

	t.Run("non-positive duration falls back", func(t *testing.T) {
		t.Setenv(ProxySessionTTLEnvVar, "0s")

		assert.Equal(t, DefaultSessionTTL, ResolveSessionTTLFromEnv())
	})
}
