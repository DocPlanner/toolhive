// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
)

// This file refreshes the tools and resources of the sessions registered on this
// pod when the set of exposed backends changes. Each session's tool and resource
// store is filled once (at registration or by lazy injection), so without a
// refresh a session keeps the tool set it saw first. A refresh clears the stores
// and sends list_changed; the next tools/list or resources/list fills them again
// from the core with the live request identity (lazyInjectSessionTools /
// lazyInjectSessionResources).
//
// Scope: only sessions registered on this pod (activeClientSessions) are
// refreshed, as they are the only ones that can hold a listen stream here. Every
// pod runs its own health monitor and refreshes its own sessions.

const (
	// registryVersionCheckInterval is how often a dynamic backend registry is
	// checked for added or removed backends.
	registryVersionCheckInterval = defaultRefreshDebounceWindow

	// registryRefreshKey is the refresh-scheduler key for registry changes.
	registryRefreshKey = "backend-registry"
)

// startCapabilityRefresh hooks session refreshes to backend health changes and, for
// a dynamic registry, to registry changes. Triggers go through the debounced
// refreshScheduler. The returned function stops it.
func (s *Server) startCapabilityRefresh() func(context.Context) error {
	sched := newRefreshScheduler(defaultRefreshDebounceWindow, defaultRefreshCooldown, s.refreshSessionCapabilities)
	if reporter := s.backendHealth(); reporter != nil {
		reporter.AddOnStatusChange(func(event health.StatusChangeEvent) {
			scheduleOnExposureChange(sched, event)
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	if reg, ok := s.backendRegistry.(vmcp.DynamicRegistry); ok {
		go watchRegistryVersion(ctx, reg, sched, registryVersionCheckInterval)
	}
	return func(context.Context) error {
		cancel()
		sched.stop()
		return nil
	}
}

// scheduleOnExposureChange schedules a refresh when a backend crosses the
// exposure boundary (see health.IsStatusEligibleForExposure).
func scheduleOnExposureChange(sched *refreshScheduler, event health.StatusChangeEvent) {
	wasEligible := health.IsStatusEligibleForExposure(event.PreviousStatus)
	isEligible := health.IsStatusEligibleForExposure(event.Status)
	if wasEligible == isEligible {
		return
	}
	mode := refreshSessionsContainingBackend
	if isEligible {
		mode = refreshSessionsLackingBackend
	}
	slog.Debug("scheduling session refresh after backend exposure change",
		"backend_id", event.BackendID, "previous_status", event.PreviousStatus, "status", event.Status)
	sched.schedule(event.BackendID, mode)
}

// watchRegistryVersion schedules a refresh whenever the registry version changes,
// until ctx is cancelled.
func watchRegistryVersion(
	ctx context.Context, reg vmcp.DynamicRegistry, sched *refreshScheduler, interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	last := reg.Version()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if current := reg.Version(); current != last {
				last = current
				sched.schedule(registryRefreshKey, refreshAllSessions)
			}
		}
	}
}

// refreshSessionCapabilities clears the tool and resource store of every session
// registered on this pod and tells its client to list them again. It is the
// refreshScheduler run function; the mode is only logged, because each store is
// refilled from the core, which already reflects the change.
func (s *Server) refreshSessionCapabilities(trigger string, mode refreshTargetMode) {
	refreshed := 0
	for _, sess := range s.activeClientSessions.snapshot() {
		sessionID := sess.SessionID()
		if withTools, ok := sess.(server.SessionWithTools); ok {
			withTools.SetSessionTools(nil)
			s.notifySession(sessionID, mcp.MethodNotificationToolsListChanged)
		}
		if withResources, ok := sess.(server.SessionWithResources); ok {
			withResources.SetSessionResources(nil)
			s.notifySession(sessionID, mcp.MethodNotificationResourcesListChanged)
		}
		refreshed++
	}
	slog.Info("refreshed session capabilities after backend change",
		"trigger", trigger, "mode", mode.String(), "session_count", refreshed)
}

func (s *Server) notifySession(sessionID, method string) {
	if err := s.mcpServer.SendNotificationToSpecificClient(sessionID, method, nil); err != nil {
		slog.Debug("failed to send list_changed notification",
			"session_id", sessionID, "method", method, "error", err)
	}
}
