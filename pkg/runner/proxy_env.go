// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"log/slog"
	"os"

	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
)

// proxyProcessEnvNames lists environment variables that configure the proxy
// process itself (session TTL, health-check behaviour) rather than the MCP
// workload. Operators declare them alongside the workload env vars (for example
// MCPServer spec.env, which the Kubernetes operator only forwards to the
// workload container), so the runner mirrors them into its own environment.
var proxyProcessEnvNames = []string{
	transportsession.ProxySessionTTLEnvVar,
	"TOOLHIVE_HEALTH_CHECK_INTERVAL",
	"TOOLHIVE_HEALTH_CHECK_PING_TIMEOUT",
	"TOOLHIVE_HEALTH_CHECK_RETRY_DELAY",
	"TOOLHIVE_HEALTH_CHECK_FAILURE_THRESHOLD",
	"TOOLHIVE_HEALTH_CHECK_SHUTDOWN_ON_FAILURE",
}

// applyProxyProcessEnv copies the proxy tuning variables found in envVars into
// the process environment. Values already present in the process environment
// win, so an explicit proxy-side setting is never overridden by the workload
// configuration.
func applyProxyProcessEnv(envVars map[string]string) {
	for _, name := range proxyProcessEnvNames {
		value, ok := envVars[name]
		if !ok || value == "" {
			continue
		}
		if _, alreadySet := os.LookupEnv(name); alreadySet {
			continue
		}
		if err := os.Setenv(name, value); err != nil {
			slog.Warn("failed to apply proxy tuning env var from workload configuration",
				"name", name, "error", err)
			continue
		}
		slog.Info("applied proxy tuning env var from workload configuration",
			"name", name, "value", value)
	}
}
