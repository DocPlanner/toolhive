// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive-core/mcpcompat/server"
	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
	"github.com/stacklok/toolhive/pkg/vmcp/server/sessionmanager"
)

func TestPeerProbeMiddleware(t *testing.T) {
	t.Parallel()

	const (
		initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		listBody = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
		callBody = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo"}}`
		getBody  = `{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"p"}}`
	)
	tests := []struct {
		name       string
		method     string
		header     string
		body       string
		wantNext   bool
		wantMarked bool
	}{
		{"probe initialize is marked", http.MethodPost, health.ProbeHeaderValue, initBody, true, true},
		{"probe tools/list is marked", http.MethodPost, health.ProbeHeaderValue, listBody, true, true},
		{"probe tools/call is refused", http.MethodPost, health.ProbeHeaderValue, callBody, false, false},
		{"probe prompts/get is refused", http.MethodPost, health.ProbeHeaderValue, getBody, false, false},
		{"probe with an unparsable body is refused", http.MethodPost, health.ProbeHeaderValue, `not json`, false, false},
		{"probe DELETE passes", http.MethodDelete, health.ProbeHeaderValue, "", true, true},
		{"no header leaves tools/call unmarked", http.MethodPost, "", callBody, true, false},
		{"other header value leaves the context unmarked", http.MethodPost, "yes", callBody, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var called, marked, healthMarked bool
			h := peerProbeMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				called = true
				marked = isPeerProbe(r.Context())
				healthMarked = health.IsHealthCheck(r.Context())
			}))
			req := httptest.NewRequest(tc.method, "/mcp", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			if tc.header != "" {
				req.Header.Set(health.ProbeHeader, tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, tc.wantNext, called)
			assert.Equal(t, tc.wantMarked, marked)
			assert.False(t, healthMarked, "the probe header must never set the health-check marker")
			if !tc.wantNext {
				assert.Equal(t, http.StatusForbidden, rec.Code)
			}
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

	probeCtx := context.WithValue(context.Background(), peerProbeKey{}, true)
	sess := &fakeSDKSession{id: srv.vmcpSessionMgr.Generate(), tools: map[string]server.ServerTool{}}

	srv.handleSessionRegistration(probeCtx, sess)
	srv.lazyInjectSessionTools(srv.mcpServer.WithContext(probeCtx, sess), "")

	assert.False(t, state.makeWithIDCalled.Load(), "a probe must not open backend connections")
	assert.Zero(t, fc.listToolsCalls.Load(), "a probe must not list capabilities")
	assert.Empty(t, sess.tools, "a probe must not get tools injected")
	_, registered := srv.refreshSinks.Load(sess.id)
	assert.False(t, registered, "a probe must not be registered for capability refreshes")
}

// TestPeerProbeHeaderCannotCall verifies that the client-controlled probe header
// does not let an authenticated caller run calls as a health check. The
// health-check marker makes outgoing auth strategies (token exchange, XAA) use
// the vMCP's own service credentials, so a probe-marked call must never reach
// the core, and never with that marker.
func TestPeerProbeHeaderCannotCall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		params string
	}{
		{name: "tools/call", method: "tools/call", params: `{"name":"echo","arguments":{}}`},
		{name: "resources/read", method: "resources/read", params: `{"uri":"` + crossPodResourceURI + `"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shared, err := transportsession.NewLocalSessionDataStorage(time.Hour)
			require.NoError(t, err)
			t.Cleanup(func() { _ = shared.Close() })
			pod := startCrossPod(t, shared)
			sessionID := initSession(t, shared, pod, "alice")

			rec := httptest.NewRecorder()
			req := newCrossPodRequest(context.Background(), http.MethodPost, "alice", sessionID,
				`{"jsonrpc":"2.0","id":2,"method":"`+tc.method+`","params":`+tc.params+`}`)
			req.Header.Set(health.ProbeHeader, health.ProbeHeaderValue)
			pod.handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Zero(t, pod.core.healthMarkedCalls.Load(), "a call must never reach the core as a health check")
			assert.Zero(t, pod.core.callToolCalls.Load()+pod.core.readResourceCalls.Load(),
				"a probe-marked call must not reach the core")

			// The refusal does not touch the session: the owner can still use it.
			body := crossPodRPC(t, pod, "alice", sessionID, tc.method, tc.params)
			assert.NotContains(t, body, `"error"`, "the owner's session must still work")
		})
	}
}
