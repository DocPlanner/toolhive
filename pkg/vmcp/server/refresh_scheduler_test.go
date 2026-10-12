// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordedRefresh struct {
	backendID string
	mode      refreshTargetMode
}

type refreshRecorder struct {
	mu   sync.Mutex
	runs []recordedRefresh
}

func (r *refreshRecorder) run(backendID string, mode refreshTargetMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs = append(r.runs, recordedRefresh{backendID: backendID, mode: mode})
}

func (r *refreshRecorder) snapshot() []recordedRefresh {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedRefresh, len(r.runs))
	copy(out, r.runs)
	return out
}

func TestRefreshScheduler_CoalescesTriggersWithinWindow(t *testing.T) {
	t.Parallel()

	rec := &refreshRecorder{}
	sched := newRefreshScheduler(30*time.Millisecond, 0, rec.run)
	t.Cleanup(sched.stop)

	for i := 0; i < 10; i++ {
		sched.schedule("backend-a", refreshSessionsLackingBackend)
	}
	sched.schedule("backend-a", refreshSessionsContainingBackend)
	assert.Equal(t, 1, sched.pendingCount())

	require.Eventually(t, func() bool { return len(rec.snapshot()) == 1 }, time.Second, 5*time.Millisecond)
	runs := rec.snapshot()
	assert.Equal(t, "backend-a", runs[0].backendID)
	assert.Equal(t, refreshAllSessions, runs[0].mode, "lacking + containing triggers must widen to all sessions")
	assert.Equal(t, 0, sched.pendingCount())
}

func TestRefreshScheduler_EnforcesCooldownBetweenRuns(t *testing.T) {
	t.Parallel()

	rec := &refreshRecorder{}
	sched := newRefreshScheduler(5*time.Millisecond, 150*time.Millisecond, rec.run)
	t.Cleanup(sched.stop)

	start := time.Now()
	sched.schedule("backend-a", refreshSessionsContainingBackend)
	require.Eventually(t, func() bool { return len(rec.snapshot()) == 1 }, time.Second, time.Millisecond)

	sched.schedule("backend-a", refreshSessionsContainingBackend)
	require.Eventually(t, func() bool { return len(rec.snapshot()) == 2 }, time.Second, time.Millisecond)
	assert.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond,
		"second run must wait for the cooldown to elapse")

	// A different backend is not throttled by backend-a's cooldown.
	before := time.Now()
	sched.schedule("backend-b", refreshSessionsLackingBackend)
	require.Eventually(t, func() bool { return len(rec.snapshot()) == 3 }, time.Second, time.Millisecond)
	assert.Less(t, time.Since(before), 100*time.Millisecond)
}

func TestRefreshScheduler_StopCancelsPending(t *testing.T) {
	t.Parallel()

	rec := &refreshRecorder{}
	sched := newRefreshScheduler(20*time.Millisecond, 0, rec.run)

	sched.schedule("backend-a", refreshSessionsContainingBackend)
	sched.stop()
	sched.schedule("backend-b", refreshSessionsContainingBackend)

	time.Sleep(60 * time.Millisecond)
	assert.Empty(t, rec.snapshot(), "stopped scheduler must not run anything")
	assert.Equal(t, 0, sched.pendingCount())
}

func TestMergeRefreshModes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, refreshSessionsLackingBackend, mergeRefreshModes(0, refreshSessionsLackingBackend))
	assert.Equal(t, refreshSessionsLackingBackend, mergeRefreshModes(refreshSessionsLackingBackend, refreshSessionsLackingBackend))
	assert.Equal(t, refreshAllSessions, mergeRefreshModes(refreshSessionsLackingBackend, refreshSessionsContainingBackend))
	assert.Equal(t, refreshAllSessions, mergeRefreshModes(refreshAllSessions, refreshSessionsContainingBackend))
}
