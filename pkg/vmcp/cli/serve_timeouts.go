// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"time"

	"github.com/stacklok/toolhive/pkg/vmcp/config"
)

const backendResponseMargin = 5 * time.Second

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

func backendRequestTimeoutsFromConfig(cfg *config.Config) (time.Duration, map[string]time.Duration) {
	if cfg == nil || cfg.Operational == nil || cfg.Operational.Timeouts == nil {
		return 0, nil
	}

	timeouts := cfg.Operational.Timeouts
	perWorkload := make(map[string]time.Duration, len(timeouts.PerWorkload))
	for workloadID, timeout := range timeouts.PerWorkload {
		perWorkload[workloadID] = time.Duration(timeout)
	}

	return time.Duration(timeouts.Default), perWorkload
}

func serverWriteTimeoutFromConfig(cfg *config.Config) time.Duration {
	defaultTimeout, perWorkload := backendRequestTimeoutsFromConfig(cfg)
	maxTimeout := defaultTimeout
	for _, timeout := range perWorkload {
		if timeout > maxTimeout {
			maxTimeout = timeout
		}
	}
	if maxTimeout <= 0 {
		return 0
	}
	return maxTimeout + backendResponseMargin
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
