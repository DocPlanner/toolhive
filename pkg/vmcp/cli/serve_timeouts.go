// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"time"

	vmcpclient "github.com/stacklok/toolhive/pkg/vmcp/client"
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

// serverWriteTimeoutFromConfig returns the HTTP write timeout that lets the
// longest backend call finish and leaves backendResponseMargin to write the MCP
// response. It mirrors the backend client's choice of timeout per call: the
// per-workload value, else timeouts.default, else
// vmcpclient.DefaultBackendRequestTimeout. The server raises values below its own
// default write timeout.
func serverWriteTimeoutFromConfig(cfg *config.Config) time.Duration {
	defaultTimeout, perWorkload := backendRequestTimeoutsFromConfig(cfg)
	if defaultTimeout <= 0 {
		defaultTimeout = vmcpclient.DefaultBackendRequestTimeout
	}
	maxTimeout := defaultTimeout
	for _, timeout := range perWorkload {
		maxTimeout = max(maxTimeout, timeout)
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
