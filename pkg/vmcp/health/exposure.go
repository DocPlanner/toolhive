// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"log/slog"
	"reflect"

	"github.com/stacklok/toolhive/pkg/vmcp"
)

// IsStatusEligibleForExposure returns true when a backend should remain visible
// in vMCP discovery/session capability surfaces.
func IsStatusEligibleForExposure(status vmcp.BackendHealthStatus) bool {
	return status == "" ||
		status == vmcp.BackendHealthy ||
		status == vmcp.BackendDegraded
}

// FilterBackendsForExposure filters backends to only include those that are
// currently eligible to be exposed to sessions and discovery.
//
// Health status filtering:
//   - healthy: included
//   - degraded: included
//   - empty/zero-value: included (assume healthy when health monitoring is disabled)
//   - unhealthy: excluded
//   - unknown: excluded
//   - unauthenticated: excluded
//
// When healthStatusProvider is provided, the current health status from the
// health monitor is used. When nil, falls back to the backend registry status.
func FilterBackendsForExposure(backends []vmcp.Backend, healthStatusProvider StatusProvider) []vmcp.Backend {
	if len(backends) == 0 {
		return backends
	}

	eligible := make([]vmcp.Backend, 0, len(backends))
	excluded := 0

	for i := range backends {
		backend := &backends[i]

		healthStatus := backend.HealthStatus
		if !isNilStatusProvider(healthStatusProvider) {
			if status, exists := healthStatusProvider.QueryBackendStatus(backend.ID); exists {
				healthStatus = status
			}
		}

		if IsStatusEligibleForExposure(healthStatus) {
			eligible = append(eligible, *backend)
			continue
		}

		excluded++
		slog.Debug("excluding backend from exposure due to health status",
			"backend_name", backend.Name,
			"backend_id", backend.ID,
			"health_status", healthStatus,
		)
	}

	if excluded > 0 {
		slog.Debug("filtered backends for exposure",
			"total_backends", len(backends),
			"eligible_backends", len(eligible),
			"excluded_backends", excluded,
		)
	}

	return eligible
}

func isNilStatusProvider(provider StatusProvider) bool {
	if provider == nil {
		return true
	}

	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
