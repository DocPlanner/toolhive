// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"time"

	"github.com/stacklok/toolhive/pkg/vmcp/config"
)

func backendInitTimeoutFromConfig(cfg *config.Config) time.Duration {
	if cfg == nil || cfg.Operational == nil {
		return 0
	}

	if cfg.Operational.FailureHandling != nil && cfg.Operational.FailureHandling.HealthCheckTimeout > 0 {
		return time.Duration(cfg.Operational.FailureHandling.HealthCheckTimeout)
	}

	if cfg.Operational.Timeouts != nil && cfg.Operational.Timeouts.Default > 0 {
		return time.Duration(cfg.Operational.Timeouts.Default)
	}

	return 0
}

// sessionTTLFromConfig returns the vMCP session TTL. The --session-ttl flag
// (upstream) wins when set; otherwise the fork's config-file sessionTTL is
// used. Zero lets the server apply its default.
func sessionTTLFromConfig(flagTTL time.Duration, cfg *config.Config) time.Duration {
	if flagTTL > 0 {
		return flagTTL
	}
	if cfg == nil {
		return 0
	}
	return time.Duration(cfg.SessionTTL)
}
