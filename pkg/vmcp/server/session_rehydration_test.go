// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/aggregator"
	"github.com/stacklok/toolhive/pkg/vmcp/discovery"
	discoverymocks "github.com/stacklok/toolhive/pkg/vmcp/discovery/mocks"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
	backendmocks "github.com/stacklok/toolhive/pkg/vmcp/mocks"
	routermocks "github.com/stacklok/toolhive/pkg/vmcp/router/mocks"
	"github.com/stacklok/toolhive/pkg/vmcp/server/adapter"
	adaptermocks "github.com/stacklok/toolhive/pkg/vmcp/server/adapter/mocks"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

type hydrationTestManager struct {
	mu                       sync.Mutex
	createSessionCalls       int
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

func (*hydrationTestManager) NotifyBackendExpired(string, string) {}

func (m *hydrationTestManager) CreateSession(context.Context, string) (vmcpsession.MultiSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createSessionCalls++
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

func TestHandleSessionRegistrationImpl_HealthCheckInjectsCapabilitiesWithoutCreateSession(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	handlerFactory := adaptermocks.NewMockHandlerFactory(ctrl)
	handlerFactory.EXPECT().
		CreateToolHandler("echo").
		Return(func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("ok"), nil
		})
	handlerFactory.EXPECT().
		CreateResourceHandler("file://example").
		Return(func(context.Context, mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return nil, nil
		})

	mgr := &hydrationTestManager{}
	srv := &Server{
		vmcpSessionMgr:    mgr,
		capabilityAdapter: adapter.NewCapabilityAdapter(handlerFactory),
	}
	session := &hydrationTestSession{
		sessionID: "session-health-register",
		ch:        make(chan mcp.JSONRPCNotification, 1),
		tools:     map[string]mcpserver.ServerTool{},
		resources: map[string]mcpserver.ServerResource{},
	}

	ctx := discovery.WithDiscoveredCapabilities(
		health.WithHealthCheckMarker(context.Background()),
		&aggregator.AggregatedCapabilities{
			Tools: []vmcp.Tool{{
				Name:        "echo",
				Description: "echo tool",
				InputSchema: map[string]any{"type": "object"},
			}},
			Resources: []vmcp.Resource{{
				URI:         "file://example",
				Name:        "example",
				Description: "example resource",
			}},
		},
	)

	err := srv.handleSessionRegistrationImpl(ctx, session)
	require.NoError(t, err)

	require.Len(t, session.GetSessionTools(), 1)
	require.Len(t, session.GetSessionResources(), 1)
	assert.Zero(t, mgr.createSessionCalls)
}

func TestHandleSessionRequestInitialization_HealthCheckInjectsCapabilitiesWithoutSessionManager(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	handlerFactory := adaptermocks.NewMockHandlerFactory(ctrl)
	handlerFactory.EXPECT().
		CreateToolHandler("echo").
		Return(func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("ok"), nil
		})

	mgr := &hydrationTestManager{}
	srv := &Server{
		vmcpSessionMgr:    mgr,
		capabilityAdapter: adapter.NewCapabilityAdapter(handlerFactory),
	}
	session := &hydrationTestSession{
		sessionID: "session-health-tools-list",
		ch:        make(chan mcp.JSONRPCNotification, 1),
		tools:     map[string]mcpserver.ServerTool{},
		resources: map[string]mcpserver.ServerResource{},
	}

	ctx := discovery.WithDiscoveredCapabilities(
		health.WithHealthCheckMarker(
			mcpserver.NewMCPServer("test", "1.0.0").WithContext(context.Background(), session),
		),
		&aggregator.AggregatedCapabilities{
			Tools: []vmcp.Tool{{
				Name:        "echo",
				Description: "echo tool",
				InputSchema: map[string]any{"type": "object"},
			}},
		},
	)

	err := srv.handleSessionRequestInitialization(
		ctx,
		1,
		json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`),
	)
	require.NoError(t, err)

	require.Len(t, session.GetSessionTools(), 1)
	assert.Zero(t, mgr.getMultiSessionCalls)
	assert.Zero(t, mgr.getAdaptedToolsCalls)
	assert.Zero(t, mgr.getAdaptedResourcesCalls)
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

func TestHandler_HealthProbeSessionIsSweptAfterTTL(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRouter := routermocks.NewMockRouter(ctrl)
	mockBackendClient := backendmocks.NewMockBackendClient(ctrl)
	mockDiscoveryMgr := discoverymocks.NewMockManager(ctrl)
	mockDiscoveryMgr.EXPECT().
		Discover(gomock.Any(), gomock.Any()).
		Return(&aggregator.AggregatedCapabilities{}, nil).
		AnyTimes()

	srv, err := New(
		context.Background(),
		&Config{
			Name:           "test-vmcp",
			Version:        "1.0.0",
			EndpointPath:   "/mcp",
			SessionTTL:     50 * time.Millisecond,
			SessionFactory: testMinimalFactory(),
		},
		mockRouter,
		mockBackendClient,
		mockDiscoveryMgr,
		vmcp.NewImmutableRegistry(nil),
		nil,
	)
	require.NoError(t, err)

	handler, err := srv.Handler(context.Background())
	require.NoError(t, err)

	reqBody := bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com/mcp", reqBody)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(health.ProbeHeader, health.ProbeHeaderValue)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	sessionID := resp.Header.Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID)

	require.Eventually(t, func() bool {
		_, ok := srv.activeClientSessions.Load(sessionID)
		return ok
	}, time.Second, 10*time.Millisecond, "probe session should be registered")

	require.Eventually(t, func() bool {
		_, ok := srv.activeClientSessions.Load(sessionID)
		return !ok
	}, 2*time.Second, 10*time.Millisecond, "probe session should be swept after TTL")
}
