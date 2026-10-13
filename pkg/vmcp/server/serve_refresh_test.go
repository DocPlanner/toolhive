// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
	"github.com/stacklok/toolhive/pkg/vmcp/server/sessionmanager"
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

// notifyingSession is a fake SDK session with tool and resource stores and a
// notification channel, so a test can observe list_changed notifications.
type notifyingSession struct {
	fakeSDKResourceSession
	notifications chan mcp.JSONRPCNotification
}

func (n *notifyingSession) NotificationChannel() chan<- mcp.JSONRPCNotification {
	return n.notifications
}

// TestRefreshSessionCapabilitiesClearsAndNotifies verifies that a refresh clears
// the tool and resource store of a session registered on this pod, sends
// list_changed for both, and that the next request fills the stores again.
func TestRefreshSessionCapabilitiesClearsAndNotifies(t *testing.T) {
	t.Parallel()

	const uri = "file:///doc.txt"
	ctrl := gomock.NewController(t)
	tools := []vmcp.Tool{{Name: "t"}}
	factory, _ := newToolSessionFactory(t, ctrl, tools)
	fc := &fakeCore{tools: tools, resources: []vmcp.Resource{{URI: uri, Name: "doc"}}}
	srv, err := Serve(context.Background(), fc, &ServerConfig{
		SessionTTL:           time.Minute,
		SessionManagerConfig: &sessionmanager.FactoryConfig{Base: factory},
		BackendRegistry:      vmcp.NewImmutableRegistry([]vmcp.Backend{}),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	sess := &notifyingSession{
		fakeSDKResourceSession: fakeSDKResourceSession{
			fakeSDKSession: fakeSDKSession{id: srv.vmcpSessionMgr.Generate(), tools: map[string]server.ServerTool{}},
			resources:      map[string]server.ServerResource{},
		},
		notifications: make(chan mcp.JSONRPCNotification, 10),
	}
	require.NoError(t, srv.mcpServer.RegisterSession(context.Background(), sess))
	require.Contains(t, sess.tools, "t", "registration must inject the tools")
	require.Contains(t, sess.resources, uri, "registration must inject the resources")

	srv.refreshSessionCapabilities("b", refreshSessionsContainingBackend)

	assert.Empty(t, sess.tools, "refresh must clear the tool store")
	assert.Empty(t, sess.resources, "refresh must clear the resource store")
	var methods []string
	for len(sess.notifications) > 0 {
		methods = append(methods, (<-sess.notifications).Method)
	}
	assert.ElementsMatch(t, []string{
		mcp.MethodNotificationToolsListChanged, mcp.MethodNotificationResourcesListChanged,
	}, methods)

	hookCtx := srv.mcpServer.WithContext(context.Background(), sess)
	srv.lazyInjectSessionTools(hookCtx)
	srv.lazyInjectSessionResources(hookCtx)
	assert.Contains(t, sess.tools, "t", "the next request must fill the tool store again")
	assert.Contains(t, sess.resources, uri, "the next request must fill the resource store again")
}
