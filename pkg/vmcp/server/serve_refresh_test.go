// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
	"github.com/stacklok/toolhive/pkg/vmcp/server/sessionmanager"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
)

func TestScheduleOnExposureChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		from, to vmcp.BackendHealthStatus
		wantMode refreshTargetMode // 0 means no refresh
	}{
		{"backend becomes ineligible", vmcp.BackendHealthy, vmcp.BackendUnhealthy, refreshSessionsContainingBackend},
		{"backend becomes eligible", vmcp.BackendUnhealthy, vmcp.BackendHealthy, refreshSessionsLackingBackend},
		{"eligibility unchanged", vmcp.BackendHealthy, vmcp.BackendDegraded, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sched := newRefreshScheduler(time.Hour, time.Hour, func(string, refreshTargetMode) {})
			t.Cleanup(sched.stop)

			scheduleOnExposureChange(sched, health.StatusChangeEvent{
				BackendID: "b", PreviousStatus: tc.from, Status: tc.to,
			})

			sched.mu.Lock()
			defer sched.mu.Unlock()
			p, scheduled := sched.pending["b"]
			if tc.wantMode == 0 {
				assert.False(t, scheduled)
				return
			}
			require.True(t, scheduled)
			assert.Equal(t, tc.wantMode, p.mode)
		})
	}
}

func TestWatchRegistryVersionSchedulesOnChange(t *testing.T) {
	t.Parallel()

	reg := vmcp.NewDynamicRegistry(nil)
	sched := newRefreshScheduler(time.Hour, time.Hour, func(string, refreshTargetMode) {})
	t.Cleanup(sched.stop)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go watchRegistryVersion(ctx, reg, sched, 10*time.Millisecond)

	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, sched.pendingCount(), "no refresh while the registry is unchanged")

	require.NoError(t, reg.Upsert(vmcp.Backend{ID: "new"}))
	require.Eventually(t, func() bool { return sched.pendingCount() == 1 },
		2*time.Second, 10*time.Millisecond, "a registry change must schedule a refresh")
}

// TestRefreshSessionCapabilitiesTriggersSinks verifies that a refresh triggers the
// list_changed sink of each live session registered on this pod for tools,
// resources and prompts, and drops the sink of a session that ended.
func TestRefreshSessionCapabilitiesTriggersSinks(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	factory, _ := newToolSessionFactory(t, ctrl, nil)
	srv, err := Serve(context.Background(), &fakeCore{}, &ServerConfig{
		SessionTTL:           time.Minute,
		SessionManagerConfig: &sessionmanager.FactoryConfig{Base: factory},
		BackendRegistry:      vmcp.NewImmutableRegistry([]vmcp.Backend{}),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	live := srv.vmcpSessionMgr.Generate()
	var kinds []vmcpsession.ChangeKind
	srv.refreshSinks.Store(live, vmcpsession.ListChangedSink(
		func(_ context.Context, _ string, kind vmcpsession.ChangeKind) { kinds = append(kinds, kind) }))
	srv.refreshSinks.Store("ended-session", vmcpsession.ListChangedSink(
		func(context.Context, string, vmcpsession.ChangeKind) {
			t.Error("the sink of an ended session must not run")
		}))

	srv.refreshSessionCapabilities("b", refreshSessionsContainingBackend)

	assert.ElementsMatch(t, []vmcpsession.ChangeKind{
		vmcpsession.KindTools, vmcpsession.KindResources, vmcpsession.KindPrompts,
	}, kinds)
	_, kept := srv.refreshSinks.Load(live)
	assert.True(t, kept, "a live session keeps its sink")
	_, stillThere := srv.refreshSinks.Load("ended-session")
	assert.False(t, stillThere, "the sink of an ended session is dropped")
}
