// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
	"github.com/stacklok/toolhive/pkg/vmcp/server/sessionmanager"
)

func TestHealthProbeContextMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"probe header marks the context", health.ProbeHeaderValue, true},
		{"no header leaves the context unmarked", "", false},
		{"other header value leaves the context unmarked", "yes", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got bool
			h := healthProbeContextMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = health.IsHealthCheck(r.Context())
			}))
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tc.header != "" {
				req.Header.Set(health.ProbeHeader, tc.header)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestServeSkipsHealthProbeSessions verifies that a health probe from a peer vMCP
// does not create a session (no backend connections), does not list capabilities
// from the core, and is not counted as an active session.
func TestServeSkipsHealthProbeSessions(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	tools := []vmcp.Tool{{Name: "t"}}
	factory, state := newToolSessionFactory(t, ctrl, tools)
	fc := &fakeCore{tools: tools}

	srv, err := Serve(context.Background(), fc, &ServerConfig{
		SessionTTL:           time.Minute,
		SessionManagerConfig: &sessionmanager.FactoryConfig{Base: factory},
		BackendRegistry:      vmcp.NewImmutableRegistry([]vmcp.Backend{}),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	probeCtx := health.WithHealthCheckMarker(context.Background())
	sess := &fakeSDKSession{id: srv.vmcpSessionMgr.Generate(), tools: map[string]server.ServerTool{}}

	srv.handleSessionRegistration(probeCtx, sess)
	srv.lazyInjectSessionTools(srv.mcpServer.WithContext(probeCtx, sess))

	assert.False(t, state.makeWithIDCalled.Load(), "a probe must not open backend connections")
	assert.Zero(t, fc.listToolsCalls.Load(), "a probe must not list capabilities")
	assert.Empty(t, sess.tools, "a probe must not get tools injected")
	assert.Zero(t, srv.activeClientSessionCount(), "a probe must not be counted as an active session")
}
