// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

type hydrationTestManager struct {
	mu                       sync.Mutex
	getMultiSessionCalls     int
	getAdaptedToolsCalls     int
	getAdaptedResourcesCalls int
	hasSession               bool
	isTerminated             bool
	validateErr              error
	tools                    []mcpserver.ServerTool
	resources                []mcpserver.ServerResource
}

func (*hydrationTestManager) Generate() string { return "generated-session" }

func (m *hydrationTestManager) Validate(string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isTerminated, m.validateErr
}

func (*hydrationTestManager) Terminate(string) (bool, error) { return false, nil }

func (*hydrationTestManager) CreateSession(context.Context, string) (vmcpsession.MultiSession, error) {
	return nil, nil
}

func (*hydrationTestManager) RefreshSession(context.Context, string) (vmcpsession.MultiSession, error) {
	return nil, nil
}

func (m *hydrationTestManager) GetAdaptedTools(string) ([]mcpserver.ServerTool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getAdaptedToolsCalls++
	return m.tools, nil
}

func (m *hydrationTestManager) GetAdaptedResources(string) ([]mcpserver.ServerResource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getAdaptedResourcesCalls++
	return m.resources, nil
}

func (m *hydrationTestManager) GetMultiSession(string) (vmcpsession.MultiSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getMultiSessionCalls++
	if !m.hasSession {
		return nil, false
	}
	return nil, true
}

func (*hydrationTestManager) DecorateSession(string, func(sessiontypes.MultiSession) sessiontypes.MultiSession) error {
	return nil
}

func (*hydrationTestManager) ReplaceSession(context.Context, string, vmcpsession.MultiSession, vmcpsession.MultiSession) error {
	return nil
}

func (*hydrationTestManager) SetSessionMetadataValue(
	context.Context,
	string,
	vmcpsession.MultiSession,
	string,
	string,
) error {
	return nil
}

type hydrationTestSession struct {
	sessionID string
	ch        chan mcp.JSONRPCNotification
	tools     map[string]mcpserver.ServerTool
	resources map[string]mcpserver.ServerResource
}

func (*hydrationTestSession) Initialize() {}

func (*hydrationTestSession) Initialized() bool { return true }

func (s *hydrationTestSession) NotificationChannel() chan<- mcp.JSONRPCNotification { return s.ch }

func (s *hydrationTestSession) SessionID() string { return s.sessionID }

func (s *hydrationTestSession) GetSessionTools() map[string]mcpserver.ServerTool { return s.tools }

func (s *hydrationTestSession) SetSessionTools(tools map[string]mcpserver.ServerTool) {
	s.tools = tools
}

func (s *hydrationTestSession) GetSessionResources() map[string]mcpserver.ServerResource {
	return s.resources
}

func (s *hydrationTestSession) SetSessionResources(resources map[string]mcpserver.ServerResource) {
	s.resources = resources
}

func TestHandleSessionRequestInitialization_RehydratesSessionTools(t *testing.T) {
	t.Parallel()

	mgr := &hydrationTestManager{
		hasSession: true,
		tools: []mcpserver.ServerTool{{
			Tool: mcp.Tool{Name: "echo"},
		}},
	}
	srv := &Server{vmcpSessionMgr: mgr}
	session := &hydrationTestSession{
		sessionID: "session-tools",
		ch:        make(chan mcp.JSONRPCNotification, 1),
		tools:     map[string]mcpserver.ServerTool{},
		resources: map[string]mcpserver.ServerResource{},
	}

	ctx := mcpserver.NewMCPServer("test", "1.0.0").WithContext(context.Background(), session)
	err := srv.handleSessionRequestInitialization(ctx, 1, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	require.NoError(t, err)

	require.Len(t, session.GetSessionTools(), 1)
	assert.Contains(t, session.GetSessionTools(), "echo")
	assert.Equal(t, 2, mgr.getMultiSessionCalls)
	assert.Equal(t, 1, mgr.getAdaptedToolsCalls)
	assert.Zero(t, mgr.getAdaptedResourcesCalls)
}

func TestHandleSessionRequestInitialization_RehydratesSessionResources(t *testing.T) {
	t.Parallel()

	mgr := &hydrationTestManager{
		hasSession: true,
		resources: []mcpserver.ServerResource{{
			Resource: mcp.Resource{URI: "file://example"},
		}},
	}
	srv := &Server{vmcpSessionMgr: mgr}
	session := &hydrationTestSession{
		sessionID: "session-resources",
		ch:        make(chan mcp.JSONRPCNotification, 1),
		tools:     map[string]mcpserver.ServerTool{},
		resources: map[string]mcpserver.ServerResource{},
	}

	ctx := mcpserver.NewMCPServer("test", "1.0.0").WithContext(context.Background(), session)
	err := srv.handleSessionRequestInitialization(ctx, 1, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}`))
	require.NoError(t, err)

	require.Len(t, session.GetSessionResources(), 1)
	assert.Contains(t, session.GetSessionResources(), "file://example")
	assert.Equal(t, 2, mgr.getMultiSessionCalls)
	assert.Zero(t, mgr.getAdaptedToolsCalls)
	assert.Equal(t, 1, mgr.getAdaptedResourcesCalls)
}

func TestHandleSessionRequestInitialization_SkipsHydrationWhenSessionAlreadyPrimed(t *testing.T) {
	t.Parallel()

	mgr := &hydrationTestManager{hasSession: true}
	srv := &Server{vmcpSessionMgr: mgr}
	session := &hydrationTestSession{
		sessionID: "session-primed",
		ch:        make(chan mcp.JSONRPCNotification, 1),
		tools: map[string]mcpserver.ServerTool{
			"echo": {Tool: mcp.Tool{Name: "echo"}},
		},
		resources: map[string]mcpserver.ServerResource{},
	}

	ctx := mcpserver.NewMCPServer("test", "1.0.0").WithContext(context.Background(), session)
	err := srv.handleSessionRequestInitialization(ctx, 1, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	require.NoError(t, err)

	assert.Zero(t, mgr.getMultiSessionCalls)
	assert.Zero(t, mgr.getAdaptedToolsCalls)
	assert.Zero(t, mgr.getAdaptedResourcesCalls)
}

func TestHandleSessionRequestInitialization_IgnoresInitialize(t *testing.T) {
	t.Parallel()

	mgr := &hydrationTestManager{hasSession: true}
	srv := &Server{vmcpSessionMgr: mgr}
	session := &hydrationTestSession{
		sessionID: "session-initialize",
		ch:        make(chan mcp.JSONRPCNotification, 1),
		tools:     map[string]mcpserver.ServerTool{},
		resources: map[string]mcpserver.ServerResource{},
	}

	ctx := mcpserver.NewMCPServer("test", "1.0.0").WithContext(context.Background(), session)
	err := srv.handleSessionRequestInitialization(ctx, 1, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	require.NoError(t, err)

	assert.Zero(t, mgr.getMultiSessionCalls)
	assert.Zero(t, mgr.getAdaptedToolsCalls)
	assert.Zero(t, mgr.getAdaptedResourcesCalls)
}

func TestHandleSessionRequestInitialization_WaitsForInFlightRegistration(t *testing.T) {
	t.Parallel()

	mgr := &hydrationTestManager{
		hasSession: false,
		tools: []mcpserver.ServerTool{{
			Tool: mcp.Tool{Name: "echo"},
		}},
	}
	srv := &Server{vmcpSessionMgr: mgr}
	session := &hydrationTestSession{
		sessionID: "session-registration-wait",
		ch:        make(chan mcp.JSONRPCNotification, 1),
		tools:     map[string]mcpserver.ServerTool{},
		resources: map[string]mcpserver.ServerResource{},
	}

	registration := srv.beginSessionRegistration(session.sessionID)
	t.Cleanup(func() {
		srv.finishSessionRegistration(session.sessionID, registration)
	})

	go func() {
		time.Sleep(75 * time.Millisecond)
		mgr.mu.Lock()
		mgr.hasSession = true
		mgr.mu.Unlock()
		srv.finishSessionRegistration(session.sessionID, registration)
	}()

	ctx := mcpserver.NewMCPServer("test", "1.0.0").WithContext(context.Background(), session)
	start := time.Now()
	err := srv.handleSessionRequestInitialization(ctx, 1, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	require.NoError(t, err)

	assert.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
	require.Len(t, session.GetSessionTools(), 1)
	assert.Contains(t, session.GetSessionTools(), "echo")
}

func TestHandleSessionRequestInitialization_WaitsForRegistrationMarkerGraceWindow(t *testing.T) {
	t.Parallel()

	mgr := &hydrationTestManager{
		hasSession: false,
		tools: []mcpserver.ServerTool{{
			Tool: mcp.Tool{Name: "echo"},
		}},
	}
	srv := &Server{vmcpSessionMgr: mgr}
	session := &hydrationTestSession{
		sessionID: "session-registration-grace",
		ch:        make(chan mcp.JSONRPCNotification, 1),
		tools:     map[string]mcpserver.ServerTool{},
		resources: map[string]mcpserver.ServerResource{},
	}

	go func() {
		time.Sleep(25 * time.Millisecond)
		registration := srv.beginSessionRegistration(session.sessionID)
		time.Sleep(50 * time.Millisecond)
		mgr.mu.Lock()
		mgr.hasSession = true
		mgr.mu.Unlock()
		srv.finishSessionRegistration(session.sessionID, registration)
	}()

	ctx := mcpserver.NewMCPServer("test", "1.0.0").WithContext(context.Background(), session)
	start := time.Now()
	err := srv.handleSessionRequestInitialization(ctx, 1, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	require.NoError(t, err)

	assert.GreaterOrEqual(t, time.Since(start), 60*time.Millisecond)
	require.Len(t, session.GetSessionTools(), 1)
	assert.Contains(t, session.GetSessionTools(), "echo")
}
