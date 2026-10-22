// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
)

// This file refreshes the capabilities of the sessions registered on this pod
// when the set of exposed backends changes (a backend's health crosses the
// advertise boundary, or a dynamic registry adds or removes a backend). Upstream
// resyncs a session only when a connected backend sends list_changed
// (serve_list_changed.go); a backend that comes back or joins the group sends
// nothing, so without this a session keeps the capabilities it saw first.
//
// A refresh triggers each session's list_changed sink for tools, resources and
// prompts, the same coalesced resync a backend notification starts. Scope: only
// sessions registered on this pod (refreshSinks). Every pod runs its own health
// monitor and refreshes its own sessions.

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
// advertise boundary (see health.ShouldAdvertise).
func scheduleOnExposureChange(sched *refreshScheduler, event health.StatusChangeEvent) {
	wasEligible := health.ShouldAdvertise(event.PreviousStatus)
	isEligible := health.ShouldAdvertise(event.Status)
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

// refreshSessionCapabilities triggers the list_changed sink of every session
// registered on this pod, and drops the sinks of sessions that ended. It is the
// refreshScheduler run function; the mode is only logged, because each resync
// re-derives the set from the core, which already reflects the change.
func (s *Server) refreshSessionCapabilities(trigger string, mode refreshTargetMode) {
	ctx := context.Background()
	refreshed := 0
	s.refreshSinks.Range(func(key, value any) bool {
		sessionID, _ := key.(string)
		sink, _ := value.(vmcpsession.ListChangedSink)
		if terminated, err := s.vmcpSessionMgr.Validate(sessionID); terminated || err != nil || sink == nil {
			s.refreshSinks.Delete(sessionID)
			return true
		}
		for _, kind := range []vmcpsession.ChangeKind{
			vmcpsession.KindTools, vmcpsession.KindResources, vmcpsession.KindPrompts,
		} {
			sink(ctx, trigger, kind)
		}
		refreshed++
		return true
	})
	slog.Info("refreshed session capabilities after backend change",
		"trigger", trigger, "mode", mode.String(), "session_count", refreshed)
}
