// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

type registrationContextKey struct{}

type registrationContextRecordingManager struct {
	createCalled bool
	sawCanceled  bool
	sawDeadline  bool
	sawIdentity  bool
	sawValue     bool
	deadline     time.Time
}

func (m *registrationContextRecordingManager) Generate() string {
	return "generated-session"
}

func (*registrationContextRecordingManager) Validate(string) (bool, error) {
	return false, nil
}

func (*registrationContextRecordingManager) Terminate(string) (bool, error) {
	return false, nil
}

func (*registrationContextRecordingManager) NotifyBackendExpired(string, string) {}

func (m *registrationContextRecordingManager) CreateSession(
	ctx context.Context,
	_ string,
) (vmcpsession.MultiSession, error) {
	m.createCalled = true
	m.sawCanceled = ctx.Err() != nil
	m.deadline, m.sawDeadline = ctx.Deadline()

	if identity, ok := auth.IdentityFromContext(ctx); ok && identity.Subject == "subject-123" {
		m.sawIdentity = true
	}

	if value, ok := ctx.Value(registrationContextKey{}).(string); ok && value == "kept" {
		m.sawValue = true
	}

	return nil, nil
}

func (*registrationContextRecordingManager) RefreshSession(
	context.Context,
	string,
) (vmcpsession.MultiSession, error) {
	return nil, nil
}

func (*registrationContextRecordingManager) GetAdaptedTools(string) ([]mcpserver.ServerTool, error) {
	return nil, nil
}

func (*registrationContextRecordingManager) GetAdaptedResources(string) ([]mcpserver.ServerResource, error) {
	return nil, nil
}

func (*registrationContextRecordingManager) GetMultiSession(string) (vmcpsession.MultiSession, bool) {
	return nil, false
}

func (*registrationContextRecordingManager) DecorateSession(
	string,
	func(sessiontypes.MultiSession) sessiontypes.MultiSession,
) error {
	return nil
}

func (*registrationContextRecordingManager) ReplaceSession(
	context.Context,
	string,
	vmcpsession.MultiSession,
	vmcpsession.MultiSession,
) error {
	return nil
}

func (*registrationContextRecordingManager) SetSessionMetadataValue(
	context.Context,
	string,
	vmcpsession.MultiSession,
	string,
	string,
) error {
	return nil
}

type registrationContextTestSession struct {
	sessionID string
	ch        chan mcp.JSONRPCNotification
}

func (*registrationContextTestSession) Initialize() {}

func (*registrationContextTestSession) Initialized() bool {
	return true
}

func (s *registrationContextTestSession) NotificationChannel() chan<- mcp.JSONRPCNotification {
	return s.ch
}

func (s *registrationContextTestSession) SessionID() string {
	return s.sessionID
}

func TestHandleSessionRegistrationImpl_DetachesFromRequestCancellation(t *testing.T) {
	t.Parallel()

	mgr := &registrationContextRecordingManager{}
	srv := &Server{vmcpSessionMgr: mgr}
	session := &registrationContextTestSession{
		sessionID: "session-123",
		ch:        make(chan mcp.JSONRPCNotification, 1),
	}

	ctx := context.Background()
	ctx = auth.WithIdentity(ctx, &auth.Identity{
		PrincipalInfo: auth.PrincipalInfo{Subject: "subject-123"},
	})
	ctx = context.WithValue(ctx, registrationContextKey{}, "kept")

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	err := srv.handleSessionRegistrationImpl(canceledCtx, session)
	require.NoError(t, err)

	assert.True(t, mgr.createCalled)
	assert.False(t, mgr.sawCanceled)
	assert.True(t, mgr.sawDeadline)
	assert.True(t, mgr.sawIdentity)
	assert.True(t, mgr.sawValue)
}

func TestHandleSessionRegistrationImpl_BoundsDetachedContext(t *testing.T) {
	t.Parallel()

	mgr := &registrationContextRecordingManager{}
	srv := &Server{vmcpSessionMgr: mgr}
	session := &registrationContextTestSession{
		sessionID: "session-456",
		ch:        make(chan mcp.JSONRPCNotification, 1),
	}

	err := srv.handleSessionRegistrationImpl(context.Background(), session)
	require.NoError(t, err)

	require.True(t, mgr.sawDeadline)

	remaining := time.Until(mgr.deadline)
	assert.Greater(t, remaining, 40*time.Second)
	assert.LessOrEqual(t, remaining, defaultSessionRegistrationTimeout)
}
