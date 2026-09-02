// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"sync"
	"time"
)

// refreshTargetMode selects which active sessions a backend-triggered refresh
// rebuilds.
type refreshTargetMode int

const (
	// refreshSessionsLackingBackend targets sessions that were created while the
	// backend was ineligible and therefore do not expose it yet.
	refreshSessionsLackingBackend refreshTargetMode = iota + 1
	// refreshSessionsContainingBackend targets sessions that expose the backend:
	// it became ineligible, or its tool/resource list changed.
	refreshSessionsContainingBackend
	// refreshAllSessions targets both groups (a lacking and a containing trigger
	// were coalesced for the same backend).
	refreshAllSessions
)

func (m refreshTargetMode) String() string {
	switch m {
	case refreshSessionsLackingBackend:
		return "sessions_lacking_backend"
	case refreshSessionsContainingBackend:
		return "sessions_containing_backend"
	case refreshAllSessions:
		return "all_sessions"
	default:
		return "unknown"
	}
}

func mergeRefreshModes(a, b refreshTargetMode) refreshTargetMode {
	if a == 0 {
		return b
	}
	if b == 0 || a == b {
		return a
	}
	return refreshAllSessions
}

const (
	// defaultRefreshDebounceWindow coalesces refresh triggers for one backend. A
	// backend that flaps (health transitions, repeated list_changed notifications)
	// produces a single rebuild per window instead of one per event.
	defaultRefreshDebounceWindow = 15 * time.Second

	// defaultRefreshCooldown is the minimum spacing between two refresh runs for
	// the same backend. Every run tears down and rebuilds the backend connections
	// of every targeted session, so it must not happen more often than this.
	defaultRefreshCooldown = 60 * time.Second
)

type pendingRefresh struct {
	mode  refreshTargetMode
	timer *time.Timer
}

// refreshScheduler debounces and rate-limits per-backend session refreshes.
// Triggers for the same backend within the debounce window are merged into one
// run, and consecutive runs are spaced by at least the cooldown.
type refreshScheduler struct {
	mu       sync.Mutex
	window   time.Duration
	cooldown time.Duration
	pending  map[string]*pendingRefresh
	lastRun  map[string]time.Time
	stopped  bool
	now      func() time.Time
	run      func(backendID string, mode refreshTargetMode)
}

func newRefreshScheduler(
	window, cooldown time.Duration,
	run func(backendID string, mode refreshTargetMode),
) *refreshScheduler {
	return &refreshScheduler{
		window:   window,
		cooldown: cooldown,
		pending:  make(map[string]*pendingRefresh),
		lastRun:  make(map[string]time.Time),
		now:      time.Now,
		run:      run,
	}
}

// schedule records a refresh trigger for backendID. The run happens after the
// debounce window (or once the cooldown since the previous run has elapsed,
// whichever is later); triggers arriving in the meantime only widen the mode.
func (r *refreshScheduler) schedule(backendID string, mode refreshTargetMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	if p, ok := r.pending[backendID]; ok {
		p.mode = mergeRefreshModes(p.mode, mode)
		return
	}

	delay := r.window
	if last, ok := r.lastRun[backendID]; ok {
		if until := r.cooldown - r.now().Sub(last); until > delay {
			delay = until
		}
	}
	p := &pendingRefresh{mode: mode}
	p.timer = time.AfterFunc(delay, func() { r.fire(backendID) })
	r.pending[backendID] = p
}

// pendingCount returns the number of backends with a scheduled refresh.
func (r *refreshScheduler) pendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (r *refreshScheduler) fire(backendID string) {
	r.mu.Lock()
	p, ok := r.pending[backendID]
	if !ok || r.stopped {
		r.mu.Unlock()
		return
	}
	delete(r.pending, backendID)
	r.lastRun[backendID] = r.now()
	mode := p.mode
	r.mu.Unlock()

	r.run(backendID, mode)
}

// stop cancels every pending refresh and rejects new triggers.
func (r *refreshScheduler) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	for id, p := range r.pending {
		p.timer.Stop()
		delete(r.pending, id)
	}
}
