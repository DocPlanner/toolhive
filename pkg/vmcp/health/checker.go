// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package health provides health monitoring for vMCP backend MCP servers.
//
// This package implements the HealthChecker interface and provides periodic
// health monitoring with configurable intervals and failure thresholds.
package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/stacklok/toolhive/pkg/vmcp"
)

const (
	metadataKeyWorkloadType  = "workload_type"
	workloadTypeMCPServer    = "mcp_server"
	workloadStatusCheckError = "backend workload status is not healthy"
)

// healthChecker implements vmcp.HealthChecker using workload status when available,
// falling back to ListCapabilities for backends that need an active MCP probe.
type healthChecker struct {
	// client is the backend client used to communicate with backends.
	client vmcp.BackendClient

	// timeout is the timeout for health check operations.
	timeout time.Duration

	// degradedThreshold is the response time threshold for marking a backend as degraded.
	// If a health check succeeds but takes longer than this duration, the backend is marked degraded.
	// Zero means disabled (backends will never be marked degraded based on response time alone).
	degradedThreshold time.Duration
}

// NewHealthChecker creates a new health checker. Kubernetes-managed MCPServer
// backends use their reconciled workload health when available; other backends
// use BackendClient.ListCapabilities as the active health check mechanism.
//
// Parameters:
//   - client: BackendClient for communicating with backend MCP servers
//   - timeout: Maximum duration for health check operations (0 = no timeout)
//   - degradedThreshold: Response time threshold for marking backend as degraded (0 = disabled)
//
// Returns a new HealthChecker implementation.
func NewHealthChecker(
	client vmcp.BackendClient,
	timeout time.Duration,
	degradedThreshold time.Duration,
) vmcp.HealthChecker {
	return &healthChecker{
		client:            client,
		timeout:           timeout,
		degradedThreshold: degradedThreshold,
	}
}

// CheckHealth performs a health check on a backend.
// Kubernetes-managed MCPServer backends already expose container readiness through
// their CRD status, so they use that status directly to avoid opening MCP sessions
// from every periodic health check. Other backends, including remote proxies and
// external entries, fall back to ListCapabilities to validate the full MCP
// communication stack.
//
// The fallback validates:
//  1. Client creation with transport setup
//  2. MCP protocol initialization handshake
//  3. Capabilities query (tools, resources, prompts)
//
// This validates the full MCP communication stack and returns the backend's health status.
//
// Health determination logic:
//   - Success with fast response: Backend is healthy (BackendHealthy)
//   - Success with slow response (> degradedThreshold): Backend is degraded (BackendDegraded)
//   - Authentication error: Backend is unauthenticated (BackendUnauthenticated)
//   - Timeout or connection error: Backend is unhealthy (BackendUnhealthy)
//   - Other errors: Backend is unhealthy (BackendUnhealthy)
//
// The error return is informational and provides context about what failed.
// The BackendHealthStatus return indicates the categorized health state.
func (h *healthChecker) CheckHealth(ctx context.Context, target *vmcp.BackendTarget) (vmcp.BackendHealthStatus, error) {
	// Mark context as health check to bypass authentication logging
	// Health checks verify backend availability and should not require user credentials
	healthCheckCtx := WithHealthCheckMarker(ctx)

	// Apply timeout if configured (after adding health check marker)
	checkCtx := healthCheckCtx
	var cancel context.CancelFunc
	if h.timeout > 0 {
		checkCtx, cancel = context.WithTimeout(healthCheckCtx, h.timeout)
		defer cancel()
	}

	slog.Debug("performing health check for backend", "backend", target.WorkloadName, "url", target.BaseURL)

	// Track response time for degraded detection
	startTime := time.Now()

	if status, ok := statusFromManagedWorkload(target); ok {
		responseDuration := time.Since(startTime)
		if status == vmcp.BackendHealthy || status == vmcp.BackendDegraded {
			slog.Debug("health check used managed workload status",
				"backend", target.WorkloadName,
				"status", status,
				"duration", responseDuration)
			return status, nil
		}
		err := fmt.Errorf("%s: %s", workloadStatusCheckError, status)
		slog.Debug("managed workload status is unhealthy",
			"backend", target.WorkloadName,
			"status", status,
			"duration", responseDuration)
		return status, err
	}

	// Use ListCapabilities as the health check - it performs:
	// 1. Client creation with transport setup
	// 2. MCP protocol initialization handshake
	// 3. Capabilities query (tools, resources, prompts)
	// This validates the full communication stack
	_, err := h.client.ListCapabilities(checkCtx, target)
	responseDuration := time.Since(startTime)

	if err != nil {
		// Categorize the error to determine health status
		status := categorizeError(err)
		slog.Debug("health check failed for backend",
			"backend", target.WorkloadName,
			"error", err,
			"status", status,
			"duration", responseDuration)
		return status, fmt.Errorf("health check failed: %w", err)
	}

	// Check if response time indicates degraded performance
	if h.degradedThreshold > 0 && responseDuration > h.degradedThreshold {
		slog.Warn("health check succeeded but response was slow - marking as degraded",
			"backend", target.WorkloadName,
			"duration", responseDuration,
			"threshold", h.degradedThreshold)
		return vmcp.BackendDegraded, nil
	}

	slog.Debug("health check succeeded for backend", "backend", target.WorkloadName, "duration", responseDuration)
	return vmcp.BackendHealthy, nil
}

func statusFromManagedWorkload(target *vmcp.BackendTarget) (vmcp.BackendHealthStatus, bool) {
	if target == nil || target.Metadata == nil {
		return "", false
	}

	workloadType := target.Metadata[metadataKeyWorkloadType]
	if workloadType != workloadTypeMCPServer {
		return "", false
	}

	switch target.HealthStatus {
	case vmcp.BackendHealthy, vmcp.BackendDegraded, vmcp.BackendUnhealthy, vmcp.BackendUnauthenticated:
		return target.HealthStatus, true
	case vmcp.BackendUnknown, "":
		return "", false
	default:
		return "", false
	}
}

// categorizeError determines the appropriate health status based on the error type.
// This uses sentinel error checking with errors.Is() for type-safe error categorization.
// Falls back to string-based detection for backwards compatibility with non-wrapped errors.
func categorizeError(err error) vmcp.BackendHealthStatus {
	if err == nil {
		return vmcp.BackendHealthy
	}

	// 1. Type-safe detection: Check for sentinel errors using errors.Is()
	// BackendClient now wraps all errors with appropriate sentinel errors
	if errors.Is(err, vmcp.ErrAuthenticationFailed) || errors.Is(err, vmcp.ErrAuthorizationFailed) {
		return vmcp.BackendUnauthenticated
	}

	if errors.Is(err, vmcp.ErrTimeout) || errors.Is(err, vmcp.ErrCancelled) {
		return vmcp.BackendUnhealthy
	}

	if errors.Is(err, vmcp.ErrBackendUnavailable) {
		return vmcp.BackendUnhealthy
	}

	// 2. String-based detection: Fallback for backwards compatibility
	// This handles errors from sources that don't wrap with sentinel errors
	if vmcp.IsAuthenticationError(err) {
		return vmcp.BackendUnauthenticated
	}

	if vmcp.IsTimeoutError(err) || vmcp.IsConnectionError(err) {
		return vmcp.BackendUnhealthy
	}

	// Default to unhealthy for unknown errors
	return vmcp.BackendUnhealthy
}
