// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/aggregator"
	vmcpauth "github.com/stacklok/toolhive/pkg/vmcp/auth"
	"github.com/stacklok/toolhive/pkg/vmcp/auth/strategies"
	authtypes "github.com/stacklok/toolhive/pkg/vmcp/auth/types"
	vmcpconfig "github.com/stacklok/toolhive/pkg/vmcp/config"
	discoveryMocks "github.com/stacklok/toolhive/pkg/vmcp/discovery/mocks"
	"github.com/stacklok/toolhive/pkg/vmcp/mocks"
	"github.com/stacklok/toolhive/pkg/vmcp/router"
	"github.com/stacklok/toolhive/pkg/vmcp/server"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
)

// newOwnerAwareTestServer builds a vMCP server with owner-aware forwarding
// enabled and Redis-backed session storage (via miniredis). The server's own
// URL is used as SessionOwnerAdvertiseURL.
func newOwnerAwareTestServer(
	t *testing.T,
	backendURL string,
	redisAddr string,
) *httptest.Server {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockBackendClient := mocks.NewMockBackendClient(ctrl)
	mockDiscoveryMgr := discoveryMocks.NewMockManager(ctrl)
	mockBackendRegistry := mocks.NewMockBackendRegistry(ctrl)

	backend := vmcp.Backend{
		ID:            "real-backend",
		Name:          "real-backend",
		BaseURL:       backendURL,
		TransportType: "streamable-http",
	}

	mockBackendRegistry.EXPECT().List(gomock.Any()).Return([]vmcp.Backend{backend}).AnyTimes()
	mockDiscoveryMgr.EXPECT().Discover(gomock.Any(), gomock.Any()).
		Return(&aggregator.AggregatedCapabilities{}, nil).AnyTimes()
	mockDiscoveryMgr.EXPECT().Stop().AnyTimes()

	authReg := vmcpauth.NewDefaultOutgoingAuthRegistry()
	require.NoError(t, authReg.RegisterStrategy(
		authtypes.StrategyTypeUnauthenticated,
		strategies.NewUnauthenticatedStrategy(),
	))
	factory := vmcpsession.NewSessionFactory(authReg)

	// Use an unstarted server so we can learn the listener URL before
	// constructing the vMCP server (needed for SessionOwnerAdvertiseURL).
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	t.Cleanup(ts.Close)

	rt := router.NewDefaultRouter()
	srv, err := server.New(
		context.Background(),
		&server.Config{
			Host:                     "127.0.0.1",
			Port:                     0,
			SessionTTL:               5 * time.Minute,
			SessionFactory:           factory,
			SessionOwnerAdvertiseURL: ts.URL,
			SessionStorage: &vmcpconfig.SessionStorageConfig{
				Provider: "redis",
				Address:  redisAddr,
			},
		},
		rt,
		mockBackendClient,
		mockDiscoveryMgr,
		mockBackendRegistry,
		nil,
	)
	require.NoError(t, err)

	handler, err := srv.Handler(context.Background())
	require.NoError(t, err)

	// Replace the placeholder handler with the real one.
	ts.Config.Handler = handler
	return ts
}

// TestIntegration_SessionRecovery_DeadOwner verifies the full recovery path:
// a session established on one server survives after the owning pod becomes
// unreachable, and subsequent requests skip the dead-owner forward cycle.
func TestIntegration_SessionRecovery_DeadOwner(t *testing.T) {
	t.Parallel()

	backendURL := startRealMCPBackend(t)
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	// --- Server A: creates the session and becomes owner ---
	serverA := newOwnerAwareTestServer(t, backendURL, mr.Addr())

	clientA := NewMCPTestClient(t, serverA.URL)
	clientA.InitializeSession()
	waitForEchoTool(t, serverA.URL, clientA.SessionID())

	// Verify the session works on A.
	resp := clientA.CallTool("echo", map[string]any{"input": "hello from A"})
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)

	sessionID := clientA.SessionID()

	// --- Shut down Server A (simulates pod death) ---
	serverA.Close()

	// --- Server B: picks up the orphaned session ---
	serverB := newOwnerAwareTestServer(t, backendURL, mr.Addr())

	clientB := NewMCPTestClient(t, serverB.URL)
	clientB.sessionID = sessionID // reuse the session from A

	// Phase 1: first request after owner loss.
	// Server B will try to forward to A (dead), fail, fall through locally,
	// restore the session from Redis, claim ownership, and serve the request.
	resp = clientB.CallTool("echo", map[string]any{"input": "hello from B"})
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"first request after owner loss should succeed, not 404; body: %s", body)

	var rpc struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &rpc), "body: %s", body)
	require.Len(t, rpc.Result.Content, 1)
	assert.False(t, rpc.Result.IsError)
	assert.Equal(t, "hello from B", rpc.Result.Content[0].Text)

	// Phase 2: second request proves recovery is durable and the dead-owner
	// forward cycle no longer repeats.
	resp = clientB.CallTool("echo", map[string]any{"input": "still on B"})
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"second request should also succeed; body: %s", body)

	require.NoError(t, json.Unmarshal(body, &rpc), "body: %s", body)
	require.Len(t, rpc.Result.Content, 1)
	assert.Equal(t, "still on B", rpc.Result.Content[0].Text)
}
