// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"errors"
	"fmt"
	"testing"
	"time"

	mcptransport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
