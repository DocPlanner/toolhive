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

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/server/sessionmanager"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

// gatedSessionFactory holds MakeSessionWithID until release is closed, so a test
// can send a call while the session registration is still running.
type gatedSessionFactory struct {
	vmcpsession.MultiSessionFactory
	release chan struct{}
}

func (f *gatedSessionFactory) MakeSessionWithID(
	ctx context.Context, id string, identity *auth.Identity, backends []*vmcp.Backend,
) (vmcpsession.MultiSession, error) {
	<-f.release
	return f.MultiSessionFactory.MakeSessionWithID(ctx, id, identity, backends)
}

// startGatedRegistration builds a Serve server, generates a session placeholder and
// starts its registration, which blocks in the session factory until the returned
// release func is called.
func startGatedRegistration(t *testing.T) (*Server, string, func()) {
	t.Helper()
	ctrl := gomock.NewController(t)
	tools := []vmcp.Tool{{Name: "t"}}
	base, _ := newToolSessionFactory(t, ctrl, tools)
	factory := &gatedSessionFactory{MultiSessionFactory: base, release: make(chan struct{})}

	srv, err := Serve(context.Background(), &fakeCore{tools: tools}, &ServerConfig{
		SessionTTL:           time.Minute,
		SessionManagerConfig: &sessionmanager.FactoryConfig{Base: factory},
		BackendRegistry:      vmcp.NewImmutableRegistry([]vmcp.Backend{}),
	})
	require.NoError(t, err)

	sessionID := srv.vmcpSessionMgr.Generate()
	require.NotEmpty(t, sessionID)
	registered := make(chan struct{})
	go func() {
		defer close(registered)
		srv.handleSessionRegistration(context.Background(),
			&fakeSDKSession{id: sessionID, tools: map[string]server.ServerTool{}})
	}()

	released := false
	release := func() {
		if !released {
			released = true
			close(factory.release)
		}
	}
	t.Cleanup(func() {
		release()
		<-registered
		_ = srv.Stop(context.Background())
	})
	return srv, sessionID, release
}

// TestEnforceSessionBindingWaitsForRegistration covers a call that arrives after
// initialize returned the session ID but before the registration wrote the
// identity binding.
func TestEnforceSessionBindingWaitsForRegistration(t *testing.T) {
	t.Parallel()

	t.Run("call waits and succeeds once the registration finishes", func(t *testing.T) {
		t.Parallel()
		srv, sessionID, release := startGatedRegistration(t)

		result := make(chan error, 1)
		go func() { result <- srv.enforceSessionBinding(context.Background(), sessionID, nil) }()

		select {
		case err := <-result:
			t.Fatalf("enforceSessionBinding returned before the registration finished: %v", err)
		case <-time.After(150 * time.Millisecond):
		}

		release()
		select {
		case err := <-result:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("enforceSessionBinding did not return after the registration finished")
		}
	})

	t.Run("call that gives up waiting does not terminate the session", func(t *testing.T) {
		t.Parallel()
		srv, sessionID, release := startGatedRegistration(t)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		req := mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "t", Arguments: map[string]any{}}}
		res, err := srv.coreToolHandler(sessionID, "t", "")(ctx, req)
		require.NoError(t, err)
		require.True(t, res.IsError)

		isTerminated, err := srv.vmcpSessionMgr.Validate(sessionID)
		require.NoError(t, err, "the placeholder must still exist")
		assert.False(t, isTerminated, "the session must not be terminated on 'not registered yet'")

		release()
		require.Eventually(t, func() bool {
			return srv.enforceSessionBinding(context.Background(), sessionID, nil) == nil
		}, 5*time.Second, 25*time.Millisecond, "the session must be usable after the registration")
	})

	t.Run("unknown session is rejected without waiting", func(t *testing.T) {
		t.Parallel()
		srv, _, _ := startGatedRegistration(t)

		start := time.Now()
		err := srv.enforceSessionBinding(context.Background(), "no-such-session", nil)
		require.ErrorIs(t, err, sessiontypes.ErrUnauthorizedCaller)
		assert.Less(t, time.Since(start), time.Second)
	})
}
