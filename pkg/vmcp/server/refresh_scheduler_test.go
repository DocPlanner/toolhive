// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

func statusChange(backendID string, previous, current vmcp.BackendHealthStatus) health.StatusChangeEvent {
	return health.StatusChangeEvent{
		BackendID:      backendID,
		BackendName:    backendID,
		PreviousStatus: previous,
		Status:         current,
	}
}

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

// refreshTestManager only implements GetMultiSession; the embedded interface
// keeps it assignable to SessionManager.
type refreshTestManager struct {
	SessionManager
	sessions map[string]sessiontypes.MultiSession
}

func (m *refreshTestManager) GetMultiSession(sessionID string) (vmcpsession.MultiSession, bool) {
	sess, ok := m.sessions[sessionID]
	return sess, ok
}

// refreshTestMultiSession only implements GetMetadata.
type refreshTestMultiSession struct {
	sessiontypes.MultiSession
	backendIDs string
}

func (s *refreshTestMultiSession) GetMetadata() map[string]string {
	return map[string]string{vmcpsession.MetadataKeyBackendIDs: s.backendIDs}
}

func newRefreshTestServer(sessions map[string]sessiontypes.MultiSession, registered ...string) *Server {
	srv := &Server{vmcpSessionMgr: &refreshTestManager{sessions: sessions}}
	for _, id := range registered {
		srv.activeClientSessions.Store(id, &hydrationTestSession{
			sessionID: id,
			ch:        make(chan mcp.JSONRPCNotification, 1),
		})
	}
	return srv
}

func registeredSessionIDs(srv *Server) []string {
	ids := make([]string, 0)
	srv.activeClientSessions.Range(func(key, _ any) bool {
		ids = append(ids, key.(string))
		return true
	})
	return ids
}

func targetIDs(targets []refreshTarget) []string {
	ids := make([]string, 0, len(targets))
	for _, tgt := range targets {
		ids = append(ids, tgt.sessionID)
	}
	return ids
}

func TestTargetSessionsForRefresh_SelectsByModeAndDropsStaleRegistrations(t *testing.T) {
	t.Parallel()

	sessions := map[string]sessiontypes.MultiSession{
		"with-backend":    &refreshTestMultiSession{backendIDs: "argocd-mcp,kubernetes-mcp"},
		"without-backend": &refreshTestMultiSession{backendIDs: "kubernetes-mcp"},
	}
	srv := newRefreshTestServer(sessions, "with-backend", "without-backend", "expired-elsewhere")

	lacking := srv.targetSessionsForRefresh("argocd-mcp", refreshSessionsLackingBackend)
	assert.ElementsMatch(t, []string{"without-backend"}, targetIDs(lacking))
	assert.ElementsMatch(t, []string{"with-backend", "without-backend"}, registeredSessionIDs(srv),
		"registrations without a live multi-session must be dropped on the first pass")

	containing := srv.targetSessionsForRefresh("argocd-mcp", refreshSessionsContainingBackend)
	assert.ElementsMatch(t, []string{"with-backend"}, targetIDs(containing))

	all := srv.targetSessionsForRefresh("argocd-mcp", refreshAllSessions)
	assert.ElementsMatch(t, []string{"with-backend", "without-backend"}, targetIDs(all))
}

func TestHandleBackendStatusChange_OnlySchedulesOnExposureTransitions(t *testing.T) {
	t.Parallel()

	rec := &refreshRecorder{}
	srv := newRefreshTestServer(nil)
	srv.refreshSched = newRefreshScheduler(10*time.Millisecond, 0, rec.run)
	t.Cleanup(srv.refreshSched.stop)

	// healthy -> degraded keeps the backend exposed: nothing to do.
	srv.handleBackendStatusChange(statusChange("b", vmcp.BackendHealthy, vmcp.BackendDegraded))
	assert.Equal(t, 0, srv.refreshSched.pendingCount())

	// unhealthy -> degraded: sessions built without the backend need it added.
	srv.handleBackendStatusChange(statusChange("b", vmcp.BackendUnhealthy, vmcp.BackendDegraded))
	// A flap right after must be merged, not scheduled twice.
	srv.handleBackendStatusChange(statusChange("b", vmcp.BackendDegraded, vmcp.BackendUnhealthy))
	assert.Equal(t, 1, srv.refreshSched.pendingCount())

	require.Eventually(t, func() bool { return len(rec.snapshot()) == 1 }, time.Second, time.Millisecond)
	assert.Equal(t, refreshAllSessions, rec.snapshot()[0].mode)

	srv.handleBackendCapabilityChange("b")
	require.Eventually(t, func() bool { return len(rec.snapshot()) == 2 }, time.Second, time.Millisecond)
	assert.Equal(t, refreshSessionsContainingBackend, rec.snapshot()[1].mode)
}
