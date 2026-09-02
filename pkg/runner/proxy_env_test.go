// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
)

func TestApplyProxyProcessEnv(t *testing.T) {
	t.Run("mirrors proxy session ttl from workload env vars", func(t *testing.T) {
		require.NoError(t, os.Unsetenv(transportsession.ProxySessionTTLEnvVar))
		t.Cleanup(func() { _ = os.Unsetenv(transportsession.ProxySessionTTLEnvVar) })

		applyProxyProcessEnv(map[string]string{
			transportsession.ProxySessionTTLEnvVar: "24h",
			"SOME_WORKLOAD_ONLY_VAR":               "ignored",
		})

		assert.Equal(t, "24h", os.Getenv(transportsession.ProxySessionTTLEnvVar))
		_, leaked := os.LookupEnv("SOME_WORKLOAD_ONLY_VAR")
		assert.False(t, leaked, "non-allowlisted workload env vars must not leak into the proxy process")
		assert.Equal(t, 24*60*60, int(transportsession.ResolveSessionTTLFromEnv().Seconds()))
	})

	t.Run("does not override an explicit process value", func(t *testing.T) {
		t.Setenv(transportsession.ProxySessionTTLEnvVar, "3h")

		applyProxyProcessEnv(map[string]string{transportsession.ProxySessionTTLEnvVar: "24h"})

		assert.Equal(t, "3h", os.Getenv(transportsession.ProxySessionTTLEnvVar))
	})

	t.Run("ignores empty values and nil maps", func(t *testing.T) {
		require.NoError(t, os.Unsetenv("TOOLHIVE_HEALTH_CHECK_FAILURE_THRESHOLD"))

		applyProxyProcessEnv(nil)
		applyProxyProcessEnv(map[string]string{"TOOLHIVE_HEALTH_CHECK_FAILURE_THRESHOLD": ""})

		_, set := os.LookupEnv("TOOLHIVE_HEALTH_CHECK_FAILURE_THRESHOLD")
		assert.False(t, set)
	})
}
