// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/stacklok/toolhive/pkg/vmcp/config"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
)

const (
	envVMCPSessionOwnerURL = "THV_VMCP_SESSION_OWNER_URL"
	envPodIP               = "POD_IP"
	backendResponseMargin  = 5 * time.Second
)

// backendTimeoutSessionOptions translates the operational timeout settings into
// session factory options so backend init and request deadlines follow config.
func backendTimeoutSessionOptions(cfg *config.Config) []vmcpsession.MultiSessionFactoryOption {
	var opts []vmcpsession.MultiSessionFactoryOption
	if initTimeout := backendInitTimeoutFromConfig(cfg); initTimeout > 0 {
		opts = append(opts, vmcpsession.WithBackendInitTimeout(initTimeout))
	}
	requestTimeout, perWorkload := backendRequestTimeoutsFromConfig(cfg)
	if requestTimeout > 0 || len(perWorkload) > 0 {
		opts = append(opts, vmcpsession.WithBackendRequestTimeouts(requestTimeout, perWorkload))
	}
	return opts
}

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

func resolveSessionOwnerAdvertiseURL(explicit, podIP string, port int) string {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		return explicit
	}
	if podIP == "" || port <= 0 {
		return ""
	}
	return fmt.Sprintf("http://%s/mcp", net.JoinHostPort(podIP, fmt.Sprintf("%d", port)))
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
