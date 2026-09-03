// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	mcptransport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/vmcp"
	vmcpauth "github.com/stacklok/toolhive/pkg/vmcp/auth"
	"github.com/stacklok/toolhive/pkg/vmcp/auth/strategies"
	authtypes "github.com/stacklok/toolhive/pkg/vmcp/auth/types"
)

func newTestRegistry(t *testing.T) vmcpauth.OutgoingAuthRegistry {
	t.Helper()
	reg := vmcpauth.NewDefaultOutgoingAuthRegistry()
	require.NoError(t, reg.RegisterStrategy(
		authtypes.StrategyTypeUnauthenticated,
		strategies.NewUnauthenticatedStrategy(),
	))
	return reg
}

func TestCreateMCPClient_UnsupportedTransport(t *testing.T) {
	t.Parallel()

	unsupportedTypes := []string{"stdio", "grpc", "", "ws"}
	for _, transport := range unsupportedTypes {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()

			target := &vmcp.BackendTarget{
				WorkloadID:    "test-backend",
				WorkloadName:  "test-backend",
				BaseURL:       "http://localhost:9999",
				TransportType: transport,
			}

			_, err := createMCPClient(target, nil, newTestRegistry(t), time.Second)
			require.Error(t, err)
			assert.ErrorIs(t, err, vmcp.ErrUnsupportedTransport,
				"transport %q should return ErrUnsupportedTransport", transport)
		})
	}
}

func TestRequestTimeoutForWorkload(t *testing.T) {
	t.Parallel()

	perWorkload := map[string]time.Duration{
		"slow-backend": 125 * time.Second,
	}

	assert.Equal(
		t,
		125*time.Second,
		requestTimeoutForWorkload("slow-backend", 60*time.Second, perWorkload),
	)
	assert.Equal(
		t,
		60*time.Second,
		requestTimeoutForWorkload("other-backend", 60*time.Second, perWorkload),
	)
	assert.Equal(
		t,
		defaultBackendRequestTimeout,
		requestTimeoutForWorkload("other-backend", 0, nil),
	)
}

func TestIsBackendSessionLostError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "mcp-go session terminated", err: fmt.Errorf("failed to send request: %w", mcptransport.ErrSessionTerminated), want: true},
		{name: "transport dropped session id", err: errBackendSessionIDLost, want: true},
		{name: "typescript sdk sessionless 400", err: errors.New("request failed with status 400: Bad Request: Not an initialization request and no valid session ID provided."), want: true},
		{name: "go-sdk sessionless jsonrpc error", err: errors.New(`method "tools/call" is invalid during session initialization`), want: true},
		{name: "mcp-go server invalid session", err: errors.New("request failed with status 400: Invalid session ID"), want: true},
		{name: "mcp-for-argocd expired session", err: errors.New("request failed with status 400: Invalid or expired session ID: 6cce26fd-e2e2-417e-b8c2-5fded9e0b6d5"), want: true},
		{name: "ambiguous 5xx", err: errors.New("request failed with status 502: Bad Gateway"), want: false},
		{name: "network error", err: errors.New("dial tcp: connection refused"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isBackendSessionLostError(tt.err))
		})
	}
}

type identityCapturingRoundTripper struct {
	seen *auth.Identity
	ok   bool
}

func (rt *identityCapturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.seen, rt.ok = auth.IdentityFromContext(req.Context())
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

func TestIdentityRoundTripper_PrefersRequestContextIdentity(t *testing.T) {
	t.Parallel()

	captured := &auth.Identity{UpstreamTokens: map[string]string{"cognito": "stale"}}
	fresh := &auth.Identity{UpstreamTokens: map[string]string{"cognito": "fresh"}}

	tests := []struct {
		name        string
		ctxIdentity *auth.Identity
		captured    *auth.Identity
		want        *auth.Identity
	}{
		{name: "request identity wins over the captured one", ctxIdentity: fresh, captured: captured, want: fresh},
		{name: "captured identity is the fallback without a caller", captured: captured, want: captured},
		{name: "no identity at all leaves the request untouched"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := &identityCapturingRoundTripper{}
			rt := &identityRoundTripper{base: base, identity: tc.captured}

			ctx := context.Background()
			if tc.ctxIdentity != nil {
				ctx = auth.WithIdentity(ctx, tc.ctxIdentity)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://backend.local/mcp", http.NoBody)
			require.NoError(t, err)

			resp, err := rt.RoundTrip(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			if tc.want == nil {
				assert.False(t, base.ok, "no identity should be injected")
				return
			}
			require.True(t, base.ok, "identity should be injected")
			assert.Same(t, tc.want, base.seen)
		})
	}
}
